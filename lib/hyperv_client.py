"""Bounded WinRM transport for a fixed, reviewed Hyper-V PowerShell program."""

from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any

DEFAULT_CREDENTIAL_KEY = "hyperv.credentials"
MAX_INPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DNS = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")
_HOST_PATH = re.compile(r"^[A-Za-z]:\\")


class HyperVPackError(Exception):
    """An action-safe error that never contains remote output or credentials."""


COMMON_FIELDS = {"credential_key", "timeout_seconds"}
ACTION_FIELDS: dict[str, set[str]] = {
    "vm_list": {"state"},
    "vm_get": {"vm_id"},
    "vm_create": {"expected_host", "name", "generation", "memory_startup_bytes", "switch_name", "vm_host_path"},
    "vm_configure": {"expected_host", "vm_id", "name", "memory_startup_bytes", "dynamic_memory", "memory_minimum_bytes", "memory_maximum_bytes", "processor_count", "automatic_start_action", "automatic_stop_action", "checkpoint_type"},
    "vm_start": {"expected_host", "vm_id"},
    "vm_stop": {"expected_host", "vm_id"},
    "vm_restart": {"expected_host", "vm_id"},
    "vm_save": {"expected_host", "vm_id"},
    "vm_delete": {"expected_host", "vm_id", "confirmation"},
    "vhd_create": {"expected_host", "vhd_host_path", "size_bytes", "disk_type", "parent_vhd_host_path"},
    "vhd_attach": {"expected_host", "vm_id", "vhd_host_path", "controller_number", "controller_location"},
    "vhd_detach": {"expected_host", "vm_id", "vhd_host_path"},
    "vhd_resize": {"expected_host", "vhd_host_path", "size_bytes"},
    "switch_list": set(),
    "switch_create": {"expected_host", "name", "switch_type", "network_adapter_name", "allow_management_os", "confirmation"},
    "switch_delete": {"expected_host", "switch_id", "confirmation"},
    "network_adapter_connect": {"expected_host", "vm_id", "adapter_name", "switch_id"},
    "network_adapter_configure": {"expected_host", "vm_id", "adapter_name", "mac_mode", "mac_address", "vlan_id"},
    "checkpoint_list": {"vm_id"},
    "checkpoint_create": {"expected_host", "vm_id", "name"},
    "checkpoint_restore": {"expected_host", "vm_id", "checkpoint_id", "confirmation"},
    "checkpoint_delete": {"expected_host", "vm_id", "checkpoint_id", "confirmation"},
    "vm_export": {"expected_host", "vm_id", "export_host_path"},
    "vm_import": {"expected_host", "config_host_path", "mode", "generate_new_id", "vhd_destination_host_path", "vm_destination_host_path", "confirmation"},
    "vm_migrate": {"expected_host", "vm_id", "destination_host", "include_storage", "destination_storage_host_path", "allow_credential_delegation", "confirmation"},
    "replication_status": {"vm_id"},
    "job_poll": {"vm_id", "job_type", "desired_state", "poll_timeout_seconds", "poll_interval_seconds"},
}
MUTATING_ACTIONS = {
    name for name in ACTION_FIELDS
    if name not in {"vm_list", "vm_get", "switch_list", "checkpoint_list", "replication_status", "job_poll"}
}
REQUIRED_FIELDS: dict[str, set[str]] = {
    "vm_get": {"vm_id"}, "vm_create": {"name"}, "vm_configure": {"vm_id"},
    "vm_start": {"vm_id"}, "vm_stop": {"vm_id"}, "vm_restart": {"vm_id"},
    "vm_save": {"vm_id"}, "vm_delete": {"vm_id", "confirmation"},
    "vhd_create": {"vhd_host_path"},
    "vhd_attach": {"vm_id", "vhd_host_path"}, "vhd_detach": {"vm_id", "vhd_host_path"},
    "vhd_resize": {"vhd_host_path", "size_bytes"}, "switch_create": {"name", "switch_type"},
    "switch_delete": {"switch_id", "confirmation"},
    "network_adapter_connect": {"vm_id", "adapter_name", "switch_id"},
    "network_adapter_configure": {"vm_id", "adapter_name"}, "checkpoint_list": {"vm_id"},
    "checkpoint_create": {"vm_id", "name"},
    "checkpoint_restore": {"vm_id", "checkpoint_id", "confirmation"},
    "checkpoint_delete": {"vm_id", "checkpoint_id", "confirmation"},
    "vm_export": {"vm_id", "export_host_path"}, "vm_import": {"config_host_path"},
    "vm_migrate": {"vm_id", "destination_host", "allow_credential_delegation", "confirmation"},
    "replication_status": {"vm_id"}, "job_poll": {"vm_id", "job_type", "desired_state"},
}
INTEGER_RANGES = {
    "generation": (1, 2), "memory_startup_bytes": (33554432, 17592186044416),
    "memory_minimum_bytes": (33554432, 17592186044416), "memory_maximum_bytes": (33554432, 17592186044416),
    "processor_count": (1, 2048), "size_bytes": (1048576, 70368744177664),
    "controller_number": (0, 3), "controller_location": (0, 63), "vlan_id": (0, 4094),
    "poll_timeout_seconds": (1, 600), "poll_interval_seconds": (1, 30),
}
BOOLEAN_FIELDS = {"dynamic_memory", "allow_management_os", "generate_new_id", "include_storage", "allow_credential_delegation"}
ENUM_VALUES = {
    "state": {"Off", "Running", "Saved", "Paused"},
    "disk_type": {"dynamic", "fixed", "differencing"}, "switch_type": {"private", "internal", "external"},
    "mac_mode": {"dynamic", "static"}, "mode": {"copy", "register"},
    "job_type": {"vm_state", "replication_state"},
    "automatic_start_action": {"Nothing", "StartIfRunning", "Start"},
    "automatic_stop_action": {"TurnOff", "Save", "ShutDown"},
    "checkpoint_type": {"Disabled", "Standard", "Production", "ProductionOnly"},
}


def _fetch_key(key_ref: str) -> dict[str, Any]:
    if not isinstance(key_ref, str) or not key_ref.strip():
        raise HyperVPackError("credential_key must be a non-empty string")
    if not key_ref.startswith("hyperv."):
        raise HyperVPackError("credential_key must reference the hyperv. Key namespace")
    try:
        import attune
        from attune.api_client.api.secrets import get_key

        response = get_key.sync_detailed(client=attune.context.client, key_ref=key_ref)
    # SDK exceptions can carry Key contents, so retain only their type.
    except Exception as exc:  # noqa: BLE001
        raise HyperVPackError(f"could not read Hyper-V credential Key ({type(exc).__name__})") from None
    if response.status_code != 200 or response.parsed is None:
        if response.status_code == 404:
            raise HyperVPackError("Hyper-V credential Key was not found")
        raise HyperVPackError(f"could not read Hyper-V credential Key (HTTP {response.status_code})")
    value = response.parsed.data.value
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            raise HyperVPackError("Hyper-V credential Key must contain a JSON object") from None
    if not isinstance(value, dict):
        raise HyperVPackError("Hyper-V credential Key must contain an object")
    return value


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise HyperVPackError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _nonempty(value: Any, name: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise HyperVPackError(f"{name} must be a non-empty string of at most {maximum} characters without controls")
    return value


def _guid(value: Any, name: str) -> str:
    value = _nonempty(value, name, 36)
    if not _GUID.fullmatch(value):
        raise HyperVPackError(f"{name} must be a GUID")
    return value.lower()


def _host(value: Any, name: str) -> str:
    value = _nonempty(value, name, 253)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        if not _DNS.fullmatch(value):
            raise HyperVPackError(f"{name} must be a DNS name or IP address without a URL or port")
    return value.lower()


def _host_path(value: Any, name: str) -> str:
    value = _nonempty(value, name, 1024)
    if not _HOST_PATH.match(value) or any(c in value for c in "*?\"<>|"):
        raise HyperVPackError(f"{name} must be an absolute local Windows host path such as D:\\HyperV\\item")
    remainder = value[3:]
    segments = remainder.split("\\")
    if any(segment in {".", ".."} or segment.endswith((" ", ".")) or ":" in segment for segment in segments):
        raise HyperVPackError(f"{name} contains an unsafe Windows path segment")
    return value


def _validate_params(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    if operation not in ACTION_FIELDS:
        raise HyperVPackError("unsupported Hyper-V action")
    unknown = set(params) - COMMON_FIELDS - ACTION_FIELDS[operation]
    if unknown:
        raise HyperVPackError("action parameters contain unsupported fields")
    clean = dict(params)
    missing = REQUIRED_FIELDS.get(operation, set()) - {name for name, value in clean.items() if value is not None}
    if missing:
        raise HyperVPackError("action parameters are missing required fields")
    for name, bounds in INTEGER_RANGES.items():
        if name in clean and clean[name] is not None:
            clean[name] = _integer(clean[name], name, *bounds)
    for name in BOOLEAN_FIELDS:
        if name in clean and clean[name] is not None and not isinstance(clean[name], bool):
            raise HyperVPackError(f"{name} must be a boolean")
    for name, choices in ENUM_VALUES.items():
        if name in clean and clean[name] is not None and (not isinstance(clean[name], str) or clean[name] not in choices):
            raise HyperVPackError(f"{name} is invalid")
    for name in ("name", "switch_name", "adapter_name", "network_adapter_name", "mac_address", "confirmation", "desired_state"):
        if name in clean and clean[name] is not None:
            clean[name] = _nonempty(clean[name], name, 2048 if name == "confirmation" else 256)
    for name in ("vm_id", "checkpoint_id", "switch_id"):
        if name in clean:
            clean[name] = _guid(clean[name], name)
    for name in ("expected_host", "destination_host"):
        if name in clean:
            clean[name] = _host(clean[name], name)
    for name in (
        "vm_host_path", "vhd_host_path", "parent_vhd_host_path", "export_host_path",
        "config_host_path", "vhd_destination_host_path", "vm_destination_host_path",
        "destination_storage_host_path",
    ):
        if name in clean and clean[name] is not None:
            clean[name] = _host_path(clean[name], name)
    if operation in MUTATING_ACTIONS and clean.get("expected_host") is None:
        raise HyperVPackError("expected_host is required for mutating actions")
    if operation == "vhd_create":
        disk_type = clean.get("disk_type", "dynamic")
        required = "parent_vhd_host_path" if disk_type == "differencing" else "size_bytes"
        if clean.get(required) is None:
            raise HyperVPackError(f"{required} is required for this disk type")
    if (
        operation == "switch_create"
        and clean.get("switch_type") == "external"
        and (clean.get("network_adapter_name") is None or not isinstance(clean.get("allow_management_os"), bool))
    ):
        raise HyperVPackError("external switches require network_adapter_name and an explicit allow_management_os boolean")
    if operation == "network_adapter_configure":
        if clean.get("mac_mode") is None and clean.get("vlan_id") is None:
            raise HyperVPackError("at least one adapter setting is required")
        if clean.get("mac_mode") == "static" and clean.get("mac_address") is None:
            raise HyperVPackError("mac_address is required for static MAC mode")
    if operation == "vm_import" and clean.get("mode", "copy") == "copy" and not isinstance(clean.get("generate_new_id"), bool):
        raise HyperVPackError("copy import requires an explicit generate_new_id boolean")
    if operation == "vm_migrate":
        if clean.get("allow_credential_delegation") is not True:
            raise HyperVPackError("migration requires explicit credential delegation confirmation")
        if clean.get("include_storage") is True and clean.get("destination_storage_host_path") is None:
            raise HyperVPackError("destination_storage_host_path is required when include_storage is true")
    timeout = clean.get("timeout_seconds", 120)
    clean["timeout_seconds"] = _integer(timeout, "timeout_seconds", 5, 1800)
    if operation == "job_poll":
        clean["poll_timeout_seconds"] = _integer(clean.get("poll_timeout_seconds", 60), "poll_timeout_seconds", 1, 600)
        clean["poll_interval_seconds"] = _integer(clean.get("poll_interval_seconds", 5), "poll_interval_seconds", 1, 30)
        if clean["timeout_seconds"] <= clean["poll_timeout_seconds"]:
            raise HyperVPackError("timeout_seconds must exceed poll_timeout_seconds")
    return clean


def _validate_confirmation(operation: str, params: dict[str, Any]) -> None:
    expected: str | None = None
    host = params.get("expected_host")
    if operation == "vm_delete":
        expected = f"DELETE_VM:{host}:{params.get('vm_id')}"
    elif operation in {"checkpoint_restore", "checkpoint_delete"}:
        verb = "RESTORE_CHECKPOINT" if operation == "checkpoint_restore" else "DELETE_CHECKPOINT"
        expected = f"{verb}:{host}:{params.get('vm_id')}:{params.get('checkpoint_id')}"
    elif operation == "switch_delete":
        expected = f"DELETE_SWITCH:{host}:{params.get('switch_id')}"
    elif operation == "switch_create" and params.get("switch_type") == "external":
        expected = f"CREATE_EXTERNAL_SWITCH:{host}:{params.get('name')}"
    elif operation == "vm_import" and params.get("mode", "copy") == "register":
        expected = f"REGISTER_IMPORT:{host}:{params.get('config_host_path')}"
    elif operation == "vm_migrate":
        expected = f"MIGRATE_VM:{host}:{params.get('vm_id')}:{params.get('destination_host')}"
    if expected is not None and params.get("confirmation") != expected:
        raise HyperVPackError(f"confirmation must exactly equal {expected}")


def _credential_settings(credential: dict[str, Any], operation: str, params: dict[str, Any]) -> dict[str, Any]:
    allowed = {"host", "port", "username", "password", "auth", "verify_tls", "ca_cert", "allow_credssp"}
    if set(credential) - allowed:
        raise HyperVPackError("Hyper-V credential Key contains unsupported fields")
    host = _host(credential.get("host"), "credential host")
    auth = credential.get("auth", "kerberos")
    if auth not in {"kerberos", "ntlm", "credssp"}:
        raise HyperVPackError("credential auth must be kerberos, ntlm, or credssp")
    username = _nonempty(credential.get("username"), "credential username", 256)
    password = credential.get("password")
    if auth in {"ntlm", "credssp"} and (not isinstance(password, str) or not password):
        raise HyperVPackError(f"credential password is required for {auth}")
    if auth == "kerberos" and password is not None:
        raise HyperVPackError("Kerberos uses the worker ticket cache; password is not accepted in the Key")
    verify_tls = credential.get("verify_tls", True)
    if verify_tls is not True:
        raise HyperVPackError("TLS certificate verification cannot be disabled")
    port = _integer(credential.get("port", 5986), "credential port", 1, 65535)
    ca_cert = credential.get("ca_cert")
    if ca_cert is not None and (not isinstance(ca_cert, str) or not ca_cert.strip() or len(ca_cert) > 1024 * 1024):
        raise HyperVPackError("credential ca_cert must be a non-empty PEM string no larger than 1 MiB")
    if operation in MUTATING_ACTIONS and params["expected_host"].lower() != host.lower():
        raise HyperVPackError("expected_host does not match the credential profile host")
    if auth == "credssp":
        if operation != "vm_migrate":
            raise HyperVPackError("CredSSP is restricted to the migration action")
        if credential.get("allow_credssp") is not True or params.get("allow_credential_delegation") is not True:
            raise HyperVPackError("CredSSP migration requires profile and action credential-delegation opt-in")
    elif params.get("allow_credential_delegation") is True:
        raise HyperVPackError("credential delegation is supported only by an explicitly enabled CredSSP migration profile")
    return {"host": host, "port": port, "username": username, "password": password, "auth": auth, "ca_cert": ca_cert}


def _load_script() -> str:
    return Path(__file__).with_name("hyperv.ps1").read_text(encoding="utf-8")


def _run_winrm(settings: dict[str, Any], payload: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    try:
        from winrm.exceptions import WinRMOperationTimeoutError
        from winrm.protocol import Protocol
    except ImportError:
        raise HyperVPackError("pywinrm runtime dependency is unavailable") from None

    raw_payload = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(raw_payload) > MAX_INPUT_BYTES:
        raise HyperVPackError("encoded action parameters exceed the 64 KiB limit")
    environment = {"ATTUNE_HYPERV_INPUT_B64": base64.b64encode(raw_payload).decode("ascii")}
    encoded_script = base64.b64encode(_load_script().encode("utf-16-le")).decode("ascii")
    operation_timeout = min(20, max(4, timeout_seconds - 2))
    protocol_kwargs: dict[str, Any] = {
        "endpoint": f"https://{settings['host']}:{settings['port']}/wsman",
        "transport": settings["auth"],
        "username": settings["username"],
        "password": settings["password"],
        "server_cert_validation": "validate",
        "operation_timeout_sec": operation_timeout,
        "read_timeout_sec": operation_timeout + 10,
        "message_encryption": "auto",
        "kerberos_delegation": False,
        "proxy": None,
    }
    stdout = bytearray()
    stderr = bytearray()
    shell_id = command_id = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="attune-hyperv-") as directory:
            if settings["ca_cert"]:
                ca_path = Path(directory, "ca.pem")
                ca_path.write_text(settings["ca_cert"], encoding="utf-8")
                os.chmod(ca_path, 0o600)
                protocol_kwargs["ca_trust_path"] = str(ca_path)
            protocol = Protocol(**protocol_kwargs)
            shell_id = protocol.open_shell(env_vars=environment, noprofile=True, codepage=65001)
            command_id = protocol.run_command(
                shell_id,
                "powershell.exe",
                ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_script],
                skip_cmd_shell=True,
            )
            while True:
                if time.monotonic() - started > timeout_seconds:
                    raise HyperVPackError("Hyper-V action exceeded its bounded timeout")
                try:
                    out, err, status, done = protocol.get_command_output_raw(shell_id, command_id)
                except WinRMOperationTimeoutError:
                    continue
                stdout.extend(out)
                stderr.extend(err)
                if len(stdout) + len(stderr) > MAX_OUTPUT_BYTES:
                    raise HyperVPackError("Hyper-V action output exceeded the 4 MiB limit")
                if done:
                    if status != 0:
                        raise HyperVPackError("Hyper-V host rejected the operation")
                    break
            protocol.cleanup_command(shell_id, command_id)
            command_id = None
            protocol.close_shell(shell_id)
            shell_id = None
    except HyperVPackError:
        raise
    # WinRM exceptions may contain response bodies or credential-bearing headers.
    except Exception as exc:  # noqa: BLE001
        raise HyperVPackError(f"WinRM request failed ({type(exc).__name__})") from None
    finally:
        if "protocol" in locals():
            if command_id is not None and shell_id is not None:
                try:
                    protocol.cleanup_command(shell_id, command_id)
                except Exception:  # noqa: BLE001
                    command_id = None
            if shell_id is not None:
                try:
                    protocol.close_shell(shell_id)
                except Exception:  # noqa: BLE001
                    try:
                        protocol.transport.close_session()
                    except Exception:  # noqa: BLE001
                        shell_id = None
    try:
        result = json.loads(stdout.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise HyperVPackError("Hyper-V host returned invalid structured output") from None
    if not isinstance(result, dict) or set(result) != {"operation", "target_host", "data", "meta"}:
        raise HyperVPackError("Hyper-V host returned an unexpected output schema")
    if result["operation"] != payload["operation"]:
        raise HyperVPackError("Hyper-V host returned an output operation mismatch")
    return result


def execute_action(operation: str, params: dict[str, Any]) -> dict[str, Any]:
    clean = _validate_params(operation, params)
    _validate_confirmation(operation, clean)
    key_ref = clean.pop("credential_key", DEFAULT_CREDENTIAL_KEY)
    timeout = clean.pop("timeout_seconds")
    settings = _credential_settings(_fetch_key(key_ref), operation, clean)
    clean["operation"] = operation
    return _run_winrm(settings, clean, timeout)

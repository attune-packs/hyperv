from __future__ import annotations

import base64
import io
import json
import os
import re
import sys
import types
import unittest
from pathlib import Path
from typing import ClassVar
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib import hyperv_client as client

VM_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
CHECKPOINT_ID = "11111111-2222-4333-8444-555555555555"
SWITCH_ID = "99999999-8888-4777-8666-555555555555"


class MetadataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actions = {
            path.stem: path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "actions").glob("*.yaml"))
        }

    def test_curated_action_inventory(self):
        self.assertEqual(set(client.ACTION_FIELDS), set(self.actions))
        self.assertEqual(27, len(self.actions))

    def test_all_contracts_are_flat_json_with_structured_output(self):
        forbidden = re.compile(r"(?m)^  (script|command|shell|arguments|password|username|endpoint):")
        for name, text in self.actions.items():
            with self.subTest(action=name):
                expected = {
                    "ref": f"hyperv.{name}", "runner_type": "python", "runtime_version": '\">=3.10\"',
                    "entry_point": "hyperv_action.py", "parameter_delivery": "stdin",
                    "parameter_format": "json", "output_format": "json",
                }
                for field, value in expected.items():
                    self.assertRegex(text, rf"(?m)^{field}: {re.escape(value)}$")
                self.assertIn("default_execution_permission_set_refs: [standard]", text)
                self.assertRegex(text, r"credential_key: \{[^\n]*default: hyperv\.credentials[^\n]*\}")
                for field in ("operation", "target_host", "data", "meta"):
                    self.assertRegex(text, rf"(?m)^  {field}: \{{type:")
                self.assertNotRegex(text, forbidden)

    def test_contract_parameter_names_exactly_match_runtime_allowlists(self):
        for name, text in self.actions.items():
            with self.subTest(action=name):
                block = text.split("parameters:", 1)[1].split("\noutput:", 1)[0]
                names = set(re.findall(r"(?m)^  ([a-z][a-z0-9_]*):", block))
                self.assertEqual(client.COMMON_FIELDS | client.ACTION_FIELDS[name], names)

    def test_source_version_license_and_notice_are_attributed(self):
        revision = "32dfae76bfc9bdf8412bb96701e2d563f9e82023"
        pack = (ROOT / "pack.yaml").read_text(encoding="utf-8")
        self.assertIn(f'source_revision: "{revision}"', pack)
        self.assertIn('source_version: "1.0.0"', pack)
        self.assertIn('license: "Apache-2.0"', pack)
        self.assertIn(revision, (ROOT / "NOTICE").read_text(encoding="utf-8"))
        self.assertIn("212 YAML action definitions", (ROOT / "SOURCE.md").read_text(encoding="utf-8"))
        self.assertIn("Apache License", (ROOT / "LICENSE").read_text(encoding="utf-8"))

    def test_reviewed_powershell_has_no_dynamic_execution_or_arbitrary_processes(self):
        script = (ROOT / "lib" / "hyperv.ps1").read_text(encoding="utf-8")
        for forbidden in ("Invoke-Expression", "ScriptBlock]::Create", "Start-Process", "cmd.exe", "Invoke-Command"):
            self.assertNotIn(forbidden, script)
        self.assertIn("$env:ATTUNE_HYPERV_INPUT_B64", script)
        self.assertIn("ConvertFrom-Json", script)
        self.assertIn("ConvertTo-Json -Compress", script)
        self.assertIn("Assert-TargetHost", script)
        self.assertIn("Assert-Confirmation", script)
        self.assertNotIn("$script:Params.script", script)


class ValidationTests(unittest.TestCase):
    def test_unknown_or_arbitrary_execution_fields_are_rejected(self):
        for field in ("script", "command", "arguments", "force", "privileged", "run_as"):
            with self.subTest(field=field), self.assertRaisesRegex(client.HyperVPackError, "unsupported fields"):
                client._validate_params("vm_get", {"vm_id": VM_ID, field: "malicious"})

    def test_ids_are_strict_and_normalized(self):
        params = client._validate_params("vm_get", {"vm_id": VM_ID.upper()})
        self.assertEqual(VM_ID, params["vm_id"])
        for value in ("vm-name", "../bad", "*", "{aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee}"):
            with self.subTest(value=value), self.assertRaises(client.HyperVPackError):
                client._validate_params("vm_get", {"vm_id": value})

    def test_host_paths_reject_worker_unc_relative_wildcard_and_traversal_paths(self):
        bad = [
            "/home/worker/export", "relative\\disk.vhdx", r"\\server\share\disk.vhdx",
            r"D:\HyperV\..\Windows", r"D:\HyperV\*.vhdx", r"D:\HyperV\disk.vhdx:secret",
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(client.HyperVPackError):
                client._validate_params("vhd_resize", {
                    "expected_host": "hv01.example.com", "vhd_host_path": value, "size_bytes": 1024 * 1024,
                })
        good = client._validate_params("vhd_resize", {
            "expected_host": "hv01.example.com", "vhd_host_path": r"D:\HyperV\VM 01\disk.vhdx", "size_bytes": 1024 * 1024,
        })
        self.assertEqual(r"D:\HyperV\VM 01\disk.vhdx", good["vhd_host_path"])

    def test_destructive_confirmation_binds_host_and_stable_ids(self):
        params = client._validate_params("checkpoint_restore", {
            "expected_host": "hv01.example.com", "vm_id": VM_ID.upper(), "checkpoint_id": CHECKPOINT_ID.upper(),
            "confirmation": f"RESTORE_CHECKPOINT:hv01.example.com:{VM_ID}:{CHECKPOINT_ID}",
        })
        client._validate_confirmation("checkpoint_restore", params)
        params["confirmation"] = f"RESTORE_CHECKPOINT:hv02.example.com:{VM_ID}:{CHECKPOINT_ID}"
        with self.assertRaisesRegex(client.HyperVPackError, "exactly equal"):
            client._validate_confirmation("checkpoint_restore", params)

    def test_conditional_schemas_reject_unsafe_or_ambiguous_requests(self):
        cases = [
            ("vhd_create", {"expected_host": "hv01", "vhd_host_path": r"D:\d.vhdx", "disk_type": "dynamic"}),
            ("vhd_create", {"expected_host": "hv01", "vhd_host_path": r"D:\d.vhdx", "disk_type": "differencing"}),
            ("network_adapter_configure", {"expected_host": "hv01", "vm_id": VM_ID, "adapter_name": "NIC"}),
            ("vm_import", {"expected_host": "hv01", "config_host_path": r"D:\vm\id.vmcx", "mode": "copy"}),
            ("vm_migrate", {"expected_host": "hv01", "vm_id": VM_ID, "destination_host": "hv02", "allow_credential_delegation": False, "confirmation": "x"}),
        ]
        for operation, params in cases:
            with self.subTest(operation=operation), self.assertRaises(client.HyperVPackError):
                client._validate_params(operation, params)

    def test_scalar_types_are_enforced_without_schema_engine_assumptions(self):
        bad = [
            ("vm_create", {"expected_host": "hv01", "name": "vm", "generation": 1.5}),
            ("vm_configure", {"expected_host": "hv01", "vm_id": VM_ID, "dynamic_memory": "true"}),
            ("switch_create", {"expected_host": "hv01", "name": "s", "switch_type": ["external"]}),
            ("job_poll", {"vm_id": VM_ID, "job_type": "vm_state", "desired_state": {"value": "Off"}}),
        ]
        for operation, params in bad:
            with self.subTest(operation=operation), self.assertRaises(client.HyperVPackError):
                client._validate_params(operation, params)


class CredentialTests(unittest.TestCase):
    def settings(self, credential, operation="vm_get", params=None):
        return client._credential_settings(credential, operation, params or {"vm_id": VM_ID})

    def test_kerberos_uses_ticket_cache_and_rejects_password_or_unverified_tls(self):
        valid = self.settings({"host": "hv01.example.com", "username": "svc@EXAMPLE.COM", "auth": "kerberos"})
        self.assertEqual("kerberos", valid["auth"])
        bad = [
            {"host": "hv01.example.com", "username": "svc@EXAMPLE.COM", "auth": "kerberos", "password": "secret"},
            {"host": "hv01.example.com", "username": "svc@EXAMPLE.COM", "auth": "kerberos", "verify_tls": False},
            {"host": "https://hv01.example.com/wsman", "username": "svc@EXAMPLE.COM", "auth": "kerberos"},
            {"host": "hv01.example.com", "username": "svc@EXAMPLE.COM", "auth": "basic"},
            {"host": "hv01.example.com", "username": "svc@EXAMPLE.COM", "auth": "kerberos", "kerberos_delegation": True},
        ]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(client.HyperVPackError):
                self.settings(value)

    def test_ntlm_requires_password_verified_tls_and_matching_mutation_host(self):
        credential = {"host": "hv01.example.com", "username": r"EXAMPLE\svc", "password": "secret", "auth": "ntlm"}
        settings = self.settings(credential, "vm_start", {"vm_id": VM_ID, "expected_host": "hv01.example.com"})
        self.assertEqual("ntlm", settings["auth"])
        with self.assertRaisesRegex(client.HyperVPackError, "does not match"):
            self.settings(credential, "vm_start", {"vm_id": VM_ID, "expected_host": "hv02.example.com"})

    def test_credssp_is_confined_to_double_confirmed_migration(self):
        credential = {
            "host": "hv01.example.com", "username": r"EXAMPLE\svc", "password": "secret",
            "auth": "credssp", "allow_credssp": True,
        }
        with self.assertRaisesRegex(client.HyperVPackError, "restricted to the migration"):
            self.settings(credential)
        params = {"expected_host": "hv01.example.com", "allow_credential_delegation": True}
        self.assertEqual("credssp", self.settings(credential, "vm_migrate", params)["auth"])
        params["allow_credential_delegation"] = False
        with self.assertRaisesRegex(client.HyperVPackError, "opt-in"):
            self.settings(credential, "vm_migrate", params)

    def test_key_namespace_and_lookup_errors_do_not_leak_details(self):
        with self.assertRaisesRegex(client.HyperVPackError, "hyperv. Key namespace"):
            client._fetch_key("other.credentials")
        fake_attune = types.ModuleType("attune")
        fake_attune.context = types.SimpleNamespace(client=object())
        fake_secrets = types.ModuleType("attune.api_client.api.secrets")
        fake_secrets.get_key = types.SimpleNamespace(sync_detailed=mock.Mock(side_effect=RuntimeError("TOP-SECRET")))
        modules = {
            "attune": fake_attune, "attune.api_client": types.ModuleType("attune.api_client"),
            "attune.api_client.api": types.ModuleType("attune.api_client.api"),
            "attune.api_client.api.secrets": fake_secrets,
        }
        with mock.patch.dict(sys.modules, modules), self.assertRaises(client.HyperVPackError) as caught:
            client._fetch_key("hyperv.credentials")
        self.assertNotIn("TOP-SECRET", str(caught.exception))


class FakeTimeout(Exception):
    pass


class FakeProtocol:
    instances: ClassVar[list[FakeProtocol]] = []
    output = None
    timeout = False

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.cleaned = []
        self.closed = []
        self.ca_content = None
        if isinstance(kwargs.get("ca_trust_path"), str):
            path = Path(kwargs["ca_trust_path"])
            self.ca_content = path.read_text(encoding="utf-8")
            self.ca_mode = path.stat().st_mode & 0o777
        self.__class__.instances.append(self)

    def open_shell(self, **kwargs):
        self.shell_kwargs = kwargs
        return "shell-id"

    def run_command(self, shell_id, executable, arguments, **kwargs):
        self.command = (shell_id, executable, list(arguments), kwargs)
        return "command-id"

    def get_command_output_raw(self, shell_id, command_id):
        if self.timeout:
            raise FakeTimeout()
        value = self.output or {
            "operation": "vm_get", "target_host": "hv01.example.com",
            "data": {"id": VM_ID}, "meta": {"changed": False, "async": False},
        }
        return json.dumps(value).encode(), b"", 0, True

    def cleanup_command(self, shell_id, command_id):
        self.cleaned.append((shell_id, command_id))

    def close_shell(self, shell_id):
        self.closed.append(shell_id)


def winrm_modules():
    protocol = types.ModuleType("winrm.protocol")
    protocol.Protocol = FakeProtocol
    exceptions = types.ModuleType("winrm.exceptions")
    exceptions.WinRMOperationTimeoutError = FakeTimeout
    return {
        "winrm": types.ModuleType("winrm"),
        "winrm.protocol": protocol,
        "winrm.exceptions": exceptions,
    }


class TransportTests(unittest.TestCase):
    def setUp(self):
        FakeProtocol.instances = []
        FakeProtocol.timeout = False
        FakeProtocol.output = None

    def settings(self, ca=None):
        return {
            "host": "hv01.example.com", "port": 5986, "username": "svc@EXAMPLE.COM",
            "password": None, "auth": "kerberos", "ca_cert": ca,
        }

    def test_constant_script_and_out_of_band_json_prevent_injection(self):
        attack = "'; Remove-VM -Name * -Force; #\n$(Get-Content env:SECRET)"
        payload = {"operation": "vm_get", "vm_id": VM_ID, "name": attack}
        with mock.patch.dict(sys.modules, winrm_modules()):
            result = client._run_winrm(self.settings("PRIVATE CA"), payload, 30)
        self.assertEqual("vm_get", result["operation"])
        instance = FakeProtocol.instances[0]
        self.assertEqual("validate", instance.kwargs["server_cert_validation"])
        self.assertFalse(instance.kwargs["kerberos_delegation"])
        self.assertIsNone(instance.kwargs["proxy"])
        self.assertEqual("PRIVATE CA", instance.ca_content)
        self.assertEqual(0o600, instance.ca_mode)
        _, executable, arguments, options = instance.command
        self.assertEqual("powershell.exe", executable)
        self.assertTrue(options["skip_cmd_shell"])
        encoded = arguments[arguments.index("-EncodedCommand") + 1]
        decoded_script = base64.b64decode(encoded).decode("utf-16-le")
        self.assertEqual((ROOT / "lib" / "hyperv.ps1").read_text(encoding="utf-8"), decoded_script)
        self.assertNotIn(attack, decoded_script)
        self.assertNotIn(attack, " ".join(arguments))
        environment = instance.shell_kwargs["env_vars"]
        decoded_payload = json.loads(base64.b64decode(environment["ATTUNE_HYPERV_INPUT_B64"]))
        self.assertEqual(attack, decoded_payload["name"])

    def test_timeout_terminates_command_and_closes_shell(self):
        FakeProtocol.timeout = True
        with (
            mock.patch.dict(sys.modules, winrm_modules()),
            mock.patch.object(client.time, "monotonic", side_effect=[0, 0, 6]),
            self.assertRaisesRegex(client.HyperVPackError, "bounded timeout"),
        ):
            client._run_winrm(self.settings(), {"operation": "vm_get", "vm_id": VM_ID}, 5)
        instance = FakeProtocol.instances[0]
        self.assertEqual([("shell-id", "command-id")], instance.cleaned)
        self.assertEqual(["shell-id"], instance.closed)

    def test_remote_stderr_and_library_errors_are_redacted(self):
        class FailedProtocol(FakeProtocol):
            def get_command_output_raw(self, shell_id, command_id):
                return b"", b"password=TOP-SECRET", 1, True

        modules = winrm_modules()
        modules["winrm.protocol"].Protocol = FailedProtocol
        with mock.patch.dict(sys.modules, modules), self.assertRaises(client.HyperVPackError) as caught:
            client._run_winrm(self.settings(), {"operation": "vm_get", "vm_id": VM_ID}, 30)
        self.assertNotIn("TOP-SECRET", str(caught.exception))

    def test_unexpected_output_schema_is_rejected(self):
        FakeProtocol.output = {"operation": "vm_get", "data": {"password": "TOP-SECRET"}}
        with mock.patch.dict(sys.modules, winrm_modules()), self.assertRaisesRegex(client.HyperVPackError, "unexpected output schema"):
            client._run_winrm(self.settings(), {"operation": "vm_get", "vm_id": VM_ID}, 30)

    def test_output_operation_mismatch_is_rejected(self):
        FakeProtocol.output = {
            "operation": "vm_delete", "target_host": "hv01.example.com", "data": {},
            "meta": {"changed": True, "async": False},
        }
        with mock.patch.dict(sys.modules, winrm_modules()), self.assertRaisesRegex(client.HyperVPackError, "operation mismatch"):
            client._run_winrm(self.settings(), {"operation": "vm_get", "vm_id": VM_ID}, 30)


class EntryPointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib.util

        spec = importlib.util.spec_from_file_location("hyperv_action_test", ROOT / "actions" / "hyperv_action.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_invalid_input_and_unknown_errors_do_not_echo_secrets(self):
        cases = [("[]", None), ('{"password":"DO-NOT-ECHO"}', RuntimeError("DO-NOT-ECHO"))]
        for raw, error in cases:
            stdout, stderr = io.StringIO(), io.StringIO()
            patch_execute = mock.patch.object(self.module, "execute_action", side_effect=error) if error else mock.patch.object(self.module, "execute_action")
            with patch_execute, mock.patch.dict(os.environ, {"ATTUNE_ACTION": "hyperv.vm_get"}), mock.patch("sys.stdin", io.StringIO(raw)), mock.patch("sys.stdout", stdout), mock.patch("sys.stderr", stderr):
                self.assertEqual(1, self.module.main())
            self.assertEqual("", stdout.getvalue())
            self.assertNotIn("DO-NOT-ECHO", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()

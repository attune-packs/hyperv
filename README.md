# Microsoft Hyper-V Attune Pack

This pack modernizes the useful requirements from the Apache-2.0 StackStorm
Exchange Hyper-V pack at revision
`32dfae76bfc9bdf8412bb96701e2d563f9e82023`. It replaces 212 generated action
definitions and stale Server 2012/2016 guidance with 27 reviewed actions based
on the currently supported Windows Server Hyper-V PowerShell module. See
[SOURCE.md](SOURCE.md) for source, version, signature, license, and Microsoft
documentation verification.

## Requirements

- Python 3.10 or newer on the selected Attune worker.
- `pywinrm` with the declared Kerberos and CredSSP extras from
  [requirements.txt](requirements.txt).
- A Kerberos client and development/runtime libraries when Kerberos is used
  (`krb5-user`/`libkrb5-dev` or distribution equivalents), plus a valid worker
  ticket obtained outside this pack.
- Windows Server 2019, 2022, or 2025 with Hyper-V and its PowerShell module.
- WinRM HTTPS (normally port 5986), a certificate trusted by the worker, and a
  least-privilege account authorized for only the required Hyper-V operations.
- An encrypted, pack-owned Attune Key such as `hyperv.credentials`.

The pack does not configure WinRM, listeners, certificates, Hyper-V migration,
replication, delegation, firewall policy, or account privileges.

## Attune Key Profiles

Kerberos is preferred for domain hosts. It uses the worker's existing ticket;
the Key does not contain a password:

```json
{
  "host": "hv01.example.com",
  "port": 5986,
  "username": "svc-attune@EXAMPLE.COM",
  "auth": "kerberos",
  "verify_tls": true,
  "ca_cert": "-----BEGIN CERTIFICATE-----\nPRIVATE-CA-PEM\n-----END CERTIFICATE-----"
}
```

NTLM supports domain or local accounts but does not prove server identity by
itself. This pack therefore requires verified HTTPS and channel binding:

```json
{
  "host": "hv01.example.com",
  "username": "EXAMPLE\\svc-attune",
  "password": "REDACTED",
  "auth": "ntlm",
  "verify_tls": true
}
```

CredSSP delegates reusable credentials to the source host and can expose them
if that host is compromised. It is rejected for every action except migration,
requires verified HTTPS, and requires both profile and action opt-in:

```json
{
  "host": "hv01.example.com",
  "username": "EXAMPLE\\svc-hyperv-migration",
  "password": "REDACTED",
  "auth": "credssp",
  "verify_tls": true,
  "allow_credssp": true
}
```

Basic authentication, plaintext WinRM, certificate-validation bypass,
Kerberos ticket delegation, URL endpoints, proxies, client scripts, shell
fragments, unmodeled profile fields, and profile Keys outside the `hyperv.`
namespace are rejected. Protect worker ticket caches and temporary storage.

## Transport Safety

Every action reads one flat JSON object from stdin. `lib/hyperv_client.py`
validates an exact allowlist, obtains the profile from Attune Key, and places
base64-encoded JSON in the WinRM shell environment. It always executes the
same reviewed `lib/hyperv.ps1` using PowerShell `-EncodedCommand`; action data
is never concatenated into PowerShell or a command line.

The transport caps input at 64 KiB, combined output at 4 MiB, action timeouts
at 5 through 1800 seconds, and polling at 600 seconds. Timeout and output-limit
paths terminate the remote command, close the shell, and close the HTTP
session. Remote exception messages and stderr are not returned because they
can contain credentials, paths, or provider details. Output is only compact
`ConvertTo-Json` data with this envelope:

```json
{
  "operation": "vm_get",
  "target_host": "hv01.example.com",
  "data": {"id": "00000000-0000-0000-0000-000000000000", "state": "Off"},
  "meta": {"changed": false, "async": false, "completed_at": "2026-08-14T12:00:00.0000000Z"}
}
```

## Worker and Host Paths

All action parameters ending in `_host_path` are interpreted by PowerShell on
the named Hyper-V host, never by the Attune worker. They must be absolute local
Windows paths such as `D:\\HyperV\\Exports`; POSIX paths, relative paths, UNC
paths, wildcards, alternate data streams, and `.`/`..` segments are rejected.
The worker only creates a private temporary CA file from the Attune Key and
deletes it after the request.

For migration, `destination_storage_host_path` is interpreted on the
destination Hyper-V host by `Move-VM`, while every other host path is on the
profiled source host. The pack never uploads, downloads, or silently copies a
worker artifact.

## Actions

| Area | Actions |
|---|---|
| VM inventory/configuration | `vm_list`, `vm_get`, `vm_create`, `vm_configure` |
| VM lifecycle | `vm_start`, `vm_stop`, `vm_restart`, `vm_save`, `vm_delete` |
| Virtual disks | `vhd_create`, `vhd_attach`, `vhd_detach`, `vhd_resize` |
| Virtual switches | `switch_list`, `switch_create`, `switch_delete` |
| VM networking | `network_adapter_connect`, `network_adapter_configure` |
| Checkpoints | `checkpoint_list`, `checkpoint_create`, `checkpoint_restore`, `checkpoint_delete` |
| Portability | `vm_export`, `vm_import`, `vm_migrate` |
| Replication/jobs | `replication_status`, `job_poll` |

Mutating VM and checkpoint actions select VMs by GUID. Switch connect/delete
uses switch GUID. Adapter names are accepted only within an already selected
VM and must resolve uniquely. Friendly names are used only where the Hyper-V
cmdlet creates a new object or has no stable selector.

## Confirmation and Semantics

The following values must match exactly after IDs and hosts are normalized:

- VM deletion: `DELETE_VM:<expected_host>:<vm_id>`
- Checkpoint restore: `RESTORE_CHECKPOINT:<expected_host>:<vm_id>:<checkpoint_id>`
- Checkpoint deletion: `DELETE_CHECKPOINT:<expected_host>:<vm_id>:<checkpoint_id>`
- Switch deletion: `DELETE_SWITCH:<expected_host>:<switch_id>`
- External switch creation: `CREATE_EXTERNAL_SWITCH:<expected_host>:<name>`
- In-place import registration: `REGISTER_IMPORT:<expected_host>:<config_host_path>`
- Migration: `MIGRATE_VM:<expected_host>:<vm_id>:<destination_host>`

`expected_host` must equal the Key profile host, and the remote script also
matches it against the actual Windows short name or FQDN before mutation. This
is separate from TLS hostname verification and protects against selecting a
valid but wrong profile.

`vm_start`, `vm_stop`, `vm_save`, VHD attach/detach/expand, and adapter connect
report `meta.changed: false` when already converged. `vm_restart`, checkpoint
creation, export, import, and migration are non-idempotent. VM deletion requires
the VM to be off and does not delete VHDs. `vm_stop` requests guest shutdown and
does not expose hard power-off. VHD shrink is rejected. External switch creation
can interrupt host networking and therefore requires an additional confirmation.

All operations are synchronous and bounded; the pack does not return fragile
PowerShell `-AsJob` IDs because those jobs are process/session scoped and do not
survive a fresh WinRM action reliably. `job_poll` instead polls durable provider
state for `vm_state` (`Off`, `Running`, `Saved`, `Paused`) or selected
`replication_state` values and returns `completed: false` on its polling timeout.

## Deliberate Gaps

- Import overwrite/conflict repair is not supported. Copy import requires an
  explicit `generate_new_id` choice; register import requires confirmation.
- Replication configuration, failover, reverse replication, and authorization
  are omitted; only status is exposed because those workflows require
  topology-specific credentials and destructive schemas.
- Migration exposes only single-destination `Move-VM`, optional whole-storage
  movement, and CredSSP. Per-VHD maps, source cleanup, destination credentials,
  unconstrained delegation, and Kerberos delegation are omitted.
- VM force-off, arbitrary force flags, passthrough PowerShell parameters, UNC
  storage, device assignment, GPU, SAN, RemoteFX, switch extensions, ACLs, and
  host-wide migration/replication configuration are not modeled.
- Live validation is not performed by unit tests. Certificate PKI, domain/SPN
  configuration, Hyper-V privileges, hardware, clustering, storage, and network
  topology remain deployment-specific responsibilities.

## Validation

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q actions lib tests
attune --output json pack check /home/david/Codebase/attune-packs/hyperv
attune pack test /home/david/Codebase/attune-packs/hyperv --detailed
```

Tests use only the Python standard library and deterministic stubs. They do not
need a Windows host, network, credentials, `pywinrm`, or undeclared packages.

## License

The verified upstream Apache License 2.0 text is included in [LICENSE](LICENSE).
Attribution and modification details are in [NOTICE](NOTICE).

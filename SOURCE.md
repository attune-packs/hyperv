# Source Verification

- Upstream: https://github.com/StackStorm-Exchange/stackstorm-hyperv
- Upstream pack version: `1.0.0`
- Verified default-branch revision: `32dfae76bfc9bdf8412bb96701e2d563f9e82023`
- Revision date: `2021-12-19T01:26:40-06:00`
- Revision signature: present but not verifiable by local Git (`E`); GitHub API reports `verified: false`, reason `unknown_key`
- Version tag: `v1.0.0` points to `f28bfdb2bfc2981eaaae6b6a479c0f618c2788d3`; the verified default revision is four commits later
- Upstream license: Apache License 2.0
- Upstream NOTICE: none at the verified revision
- Upstream inventory: 212 YAML action definitions and four Python support files

The upstream README targets Windows Server 2012 and 2016 documentation. Those
assumptions and the generated one-definition-per-cmdlet surface were not
ported. Requirements were curated against the supported Windows Server 2025
Hyper-V module reference, which also links supported Server 2019 and 2022
references, on 2026-08-14.

Authoritative references reviewed:

- https://learn.microsoft.com/en-us/powershell/module/hyper-v/?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/hyper-v/import-vm?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/hyper-v/move-vm?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/module/hyper-v/get-vmreplication?view=windowsserver2025-ps
- https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security
- https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_remote_jobs
- https://github.com/diyan/pywinrm

The Microsoft Hyper-V module page was updated 2025-05-29 and identifies source
revision `eaf901abea47f582c8a96f36f4e16b9d896f6f1e`. Microsoft remoting guidance
states that Kerberos authenticates both peers, NTLM does not authenticate the
server, WinRM encrypts messages after authentication, and CredSSP caches
delegated credentials on the remote host. This pack therefore uses verified
HTTPS for every mode, disables proxies and Kerberos delegation, and confines
CredSSP to explicitly confirmed migration.

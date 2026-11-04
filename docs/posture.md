# Posture checks

Posture checks find Windows settings that make a device easier to attack, such as SMBv1 left
on or no LAPS. They work like HardeningKitty: a list of rules, each reading a few registry
values and comparing them with a safe setting. A failed rule becomes a finding, so it shows up
as a fix on the dashboard with a risk score, a deadline and exceptions, next to the CVEs.

## How it works

1. The rules live on the server in [`intel/posture_rules.toml`](../intel/posture_rules.toml).
2. Every heartbeat returns a hash of the values the rules read. When an agent holds a different
   hash, it fetches the new read list (`POST /api/agent/posture`), reads the values, and uploads.
3. The agent reads the values with every inventory, every 4 hours, in background mode. On
   BEARONE the 30 reads add a few milliseconds.
4. The server judges the rules each time it evaluates the device. A rule whose values the agent
   has not read yet counts as "not checked", and its open finding stays open.

So a new or corrected rule reaches every agent within 15 minutes of a server deploy, with no
agent update. Editing only a rule's title or text does not change the hash, so agents are not
asked to read again. Any change to the rules file (a condition, a severity, a text) makes the
worker re-judge every device from its stored values within 30 seconds of the deploy.

## What the agent will and won't read

The read list comes from the server, so the agent limits what any list can ask for. Even
someone who controlled the server could not use it to pull data off a PC.

- **Read-only, and only these keys** (and the keys below them):
  `HKLM\SOFTWARE\Policies`, `HKLM\SOFTWARE\Microsoft\Policies`,
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies`,
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
  `HKLM\SOFTWARE\Microsoft\Windows Defender`, `HKLM\SYSTEM\CurrentControlSet\Control` and
  `HKLM\SYSTEM\CurrentControlSet\Services`. Never the SAM or SECURITY hives or user hives.
  Anything else in a read list is skipped.
- **Numbers and yes/no only.** A text value is sent only when it is a plain number (like
  AutoAdminLogon's "1"). Any other text or binary value is sent as `"set"`.
- **No secrets.** A value whose name contains password, pwd, secret, passphrase, credential or
  token is only ever sent as `"set"`. The autologon rule uses this to check that
  `DefaultPassword` exists without reading it.
- **One Windows API, no WMI or PowerShell.** Antivirus health comes from Windows Security
  Center (`WscGetSecurityProviderHealth`), which also covers third-party antivirus.
- At most 300 reads. The server checks the rules file against the same limits when it loads it,
  and the tests fail on any rule that reads outside them.

## Writing a rule

```toml
[[rule]]
id = "smb1-server"                # 1 to 32 lowercase letters, digits and dashes; never reuse one
title = "The SMBv1 file sharing server is on"   # the problem, as the device page shows it
category = "Network"
severity = "critical"             # critical | high | medium | low (see scoring.md)
applies = "all"                   # all | workstation | server
fix = "Turn off the SMBv1 server" # the fix row's name on the dashboard
why = "..."                       # shown on the fix page
how = "..."
reference = "https://..."         # optional
match = "all"                     # optional: "any" fails when any one condition holds
before_build = 26100              # optional: only Windows builds below this (for changed defaults)
when = [
  { read = 'HKLM\SYSTEM\CurrentControlSet\Services\srv', op = "exists" },
  { read = 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters:SMB1', op = "!=", value = 0, default = 1 },
]
```

- `read` is a key (checks that it exists) or `key:value`. A list means "the first one that is
  set": put the Group Policy value before the local setting.
- `op` is one of `==`, `!=`, `<`, `<=`, `>`, `>=`, `exists`, `missing`.
- `default` is what Windows does when nothing is set. Without one, a missing value makes the
  condition false (except for `missing`).
- Single quotes in TOML keep backslashes as they are.
- When a Windows default changed between versions, split the rule: one for the setting turned
  on by hand, and one with `before_build` for older builds where it is on by default. A rule
  with `before_build` is skipped when the device's build is unknown.

To add or change a rule:

1. Edit `intel/posture_rules.toml`. Check each value on a real PC first with `reg query`.
2. Run the tests (`pytest` in `server/`). They load the file and check every read and text.
3. To see what an agent would send without any network, save the reads as a JSON list and run
   `bw-agent inventory --reads reads.json` on a PC.
4. Deploy the server. Agents pick up the new list at their next heartbeat.

Removing a rule closes its open findings at the next evaluation, recorded as fixed.

## The rules

| Rule | Severity | Applies to | Fails when |
|---|---|---|---|
| `av-unhealthy` | Critical | Workstations | Security Center says antivirus is off, missing or out of date |
| `smb1-server` | Critical | All | The SMBv1 server is installed and not turned off |
| `wdigest-on` | Critical | All | WDigest keeps plain-text passwords in memory |
| `firewall-off` | High | All | Windows Firewall is off for any network type |
| `smb1-client` | High | All | The SMBv1 client is installed and not disabled |
| `ntlmv1-allowed` | High | All | LAN Manager authentication level is below 3 |
| `lm-hash-stored` | High | All | NoLMHash is 0 |
| `rdp-without-nla` | High | All | Remote Desktop is on and Network Level Authentication is off |
| `uac-off` | High | All | EnableLUA is 0 |
| `autologon-password` | High | All | Automatic sign-in is on with a stored DefaultPassword |
| `smb-signing-server` | Medium | Servers | The server does not require SMB signing |
| `llmnr-on` | Medium | All | LLMNR is not turned off by policy |
| `uac-silent-elevation` | Medium | All | Admins elevate with no prompt |
| `laps-missing` | Medium | All | Neither Windows LAPS nor legacy LAPS is set up |
| `old-tls-server` | Medium | All | TLS 1.0 or 1.1 was turned on by hand for incoming connections |
| `old-tls-default` | Medium | Servers before 2025 | TLS 1.0 or 1.1 is not turned off, so it is on by default |
| `remote-registry-auto` | Low | Workstations | Remote Registry starts automatically |
| `spooler-on-server` | Low | Servers | Print Spooler is not disabled |

## Left out on purpose

- **BitLocker.** NinjaOne already reports it, and the only reliable source is WMI.
- **PowerShell 2.0.** Its registry key stays behind on Windows 11 25H2, where 2.0 is gone, so
  it would flag PCs that are fine.
- **NetBIOS over TCP/IP.** It is set per network adapter, including old virtual ones. One test
  PC had 22, so the check would be noise until it can tell live adapters from stale ones.
- **Domain controllers** are not detected yet, so DC-only rules (and "always on DCs" advice)
  rely on the technician. Set a DC's importance to 5 on its device page.

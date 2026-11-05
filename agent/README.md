# bw-agent

The BearWatch Windows agent. It reads what is installed (Windows build and revision, installed
KBs, programs) and the security settings the server's posture rules ask for from the registry,
and reports them to the BearWatch server, which does all the matching and judging. See [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md#the-agent-light-by-design)
for how it stays light.

## Build

Needs only Docker. From the repo root:

```powershell
powershell -File agent\build.ps1
```

This cross-compiles in a container (`agent-build` in `compose.yaml`, profile `tools`) and copies
`dist\bw-agent.exe` and `agent\Cargo.lock` out.

## Install on a PC

In an elevated prompt (or the same two lines from an RMM script):

```powershell
bw-agent.exe enroll --server https://bearwatch.example.com --key bwe_...
bw-agent.exe install
```

The enrollment key comes from the dashboard (Clients and sites, Add a site) or
`bearwatch site add`. `install` copies the exe to `C:\Program Files\BearWatch` and starts the
`BearWatchAgent` service. Running `install` again with a newer exe upgrades it in place.

## Other commands

| Command | What it does |
|---|---|
| `bw-agent inventory [--reads FILE]` | Prints the JSON it would send, plus time, CPU, memory and upload size. Sends nothing. Settings come from the read list the server last sent (readable from an elevated prompt), or from `FILE`, a JSON list of reads, for testing [posture rules](../docs/posture.md). |
| `bw-agent run-once [--wua] [--force]` | One check-in now. `--wua` runs the Windows Update cross-check regardless of power and idle state. |
| `bw-agent uninstall` | Stops and removes the service and deletes `%ProgramData%\BearWatch` (the device token). |

Logs go to `%ProgramData%\BearWatch\agent.log` (1 MB, one rotated copy).

## AV and EDR exclusions

None should be needed: the agent reads the registry, makes HTTPS requests to one host, and
writes only to `%ProgramData%\BearWatch`. If a product flags it, exclude
`C:\Program Files\BearWatch\bw-agent.exe`. The exe is not code-signed yet.

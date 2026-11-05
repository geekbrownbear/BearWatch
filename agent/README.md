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
| `bw-agent run-once [--wua] [--force]` | One check-in now. `--wua` runs the Windows Update cross-check regardless of power and idle state. If this PC is the site's sensor and a scan is due, it waits for the scan too. |
| `bw-agent sensor [--out FILE]` | Runs one [sensor](#sensor-mode) scan now and writes the JSON it would send to `FILE` or the console. Sends nothing. |
| `bw-agent uninstall` | Stops and removes the service and deletes `%ProgramData%\BearWatch` (the device token). |

Logs go to `%ProgramData%\BearWatch\agent.log` (1 MB, one rotated copy).

## Sensor mode

One PC per site can be the site's sensor. The server picks it and tells it how often to scan
(in the heartbeat plan); nothing is set on the PC. The sensor finds the other devices on its
local networks, such as printers, NAS boxes, cameras and PCs without the agent, and reports
them with their open ports and any risky settings.

- **What it scans:** the IPv4 networks of this PC's active adapters, private ranges only
  (10/8, 172.16/12, 192.168/16), at most 4. A network larger than a /22 is narrowed to the
  /24 around the PC. Link-local and carrier-grade NAT ranges are skipped.
- **How:** ping, ARP and a small TCP probe to find devices; reverse DNS, NetBIOS, mDNS, LLMNR
  and UPnP for names; MAC vendor from the IEEE registry; 53 common TCP ports with banners. At
  most 64 threads and normal timeouts; a /24 takes about half a minute.
- **Checks:** 14 configuration checks from [Proton IP Scanner](https://github.com/geekbrownbear/proton-network-scanner)
  (ids `PIS-0001` to `PIS-0014`), such as Redis or Elasticsearch without a password,
  anonymous FTP or MQTT, Telnet, and login pages over plain HTTP. They are non-destructive:
  they only read what a service offers to anyone who connects, or try the documented
  anonymous access, then disconnect. Nothing is written, changed or exploited.
  Requests go only to services identified by their port or their greeting. Printing ports
  (515, 9100 to 9102) are only connected to, never written to, because a printer prints
  whatever arrives there. When a check cannot finish (timeout, no answer), the port is listed
  in the host's `unchecked_ports`, so the server keeps its earlier issues open.
- **How often:** every `interval_minutes` from the plan. The scan runs on its own thread, so
  heartbeats and service stops never wait for it. A failed scan or upload is retried at the
  next interval. If the server answers that this PC is no longer the sensor, it stops until
  the server asks again.

The sensor code is adapted from Proton IP Scanner (GPL-3.0-or-later). The MAC vendor list is
the IEEE registry data from the `oui-data` package, BSD-2-Clause, see
[src/sensor/oui-LICENSE.txt](src/sensor/oui-LICENSE.txt).

## AV and EDR exclusions

None should be needed: the agent reads the registry, makes HTTPS requests to one host, and
writes only to `%ProgramData%\BearWatch`. On the site's sensor PC it also scans the local
network, which some EDR and network IDS products report as a port scan. If a product flags
it, exclude `C:\Program Files\BearWatch\bw-agent.exe`. The exe is not code-signed yet.

# Network sensor

The agent sees what is installed on a Windows PC. It can't see the printer, the camera, the
NAS or the personal laptop on the same network. Sensor mode fills that gap: one enrolled PC per
site scans its own network every few hours and reports what it finds.

## What it does

- **Finds devices.** Ping, ARP and a TCP probe find every device on the PC's local subnets. For
  each one it records the IP address, the hardware (MAC) address and its maker, and up to four
  names (DNS, NetBIOS, mDNS and UPnP).
- **Lists devices without the agent.** Each device is matched to an enrolled PC by its MAC
  address, which agent 0.3.0 and later report in the inventory, or failing that by its name.
  Matching covers every site of the client, since one office network often holds PCs enrolled
  under more than one site. What is left is the list of devices without the agent.
- **Flags new devices.** The first scan after a sensor is picked is the baseline. A device first
  seen after that is "new" for a week, until a technician marks it as known or installs the
  agent on it.
- **Checks common services.** About 50 common ports are checked (Proton's "vulnerable services"
  list), with banners. Fourteen checks from Proton look for unsafe settings that have no CVE
  number, like a Redis or MongoDB that takes commands without a password, anonymous FTP, or
  Telnet. Each problem is a network issue with a severity from its CVSS score and a fix.
  Checks scored 0 ("Remote Desktop reachable", "Software version detected") are notes: they
  show on the host's row but are never counted as issues or put in the client report.

The scan is non-destructive. It only reads what a device shows to anyone who connects, or tries
the documented anonymous or guest access (FTP `anonymous`, MQTT with no credentials). Nothing is
written, changed or exploited.

## Setting it up

1. Pick a PC that stays on, wired if possible, with agent 0.3.0 or later.
2. On **Clients and sites**, choose it in the site's **Network sensor** column, or run
   `bearwatch site sensor <site id> <device id>` (`none` turns it off).
3. The PC's next heartbeat (within 15 minutes) tells it to scan. Results show on the site's
   **Network** page, linked from the client page.

The scan runs every 4 hours (`BEARWATCH_SENSOR_INTERVAL_MINUTES`). If no scan arrives for two
intervals plus an hour, the site shows the sensor as silent: a silent sensor is never shown as
"nothing found".

## What it scans

- The IPv4 subnets of the PC's adapters that are up and in private ranges (10/8, 172.16/12,
  192.168/16), at most 4. Link-local and carrier-grade NAT ranges are skipped.
- A subnet bigger than /22 is cut to the /24 around the PC's own address, so a /16 office
  network never turns into a 65,000-address sweep.
- At most 64 probes at a time, with normal timeouts, to stay gentle on client networks.

Devices on other subnets (behind a router) have no visible MAC address. They are kept by IP and
can't be matched by MAC.

## How issues open and close

- An issue stays open until a scan reaches the device again and the check passes. Then it is
  marked fixed.
- A device that is switched off keeps its issues: no answer is not evidence of a fix.
- A fixed issue that comes back reopens, and its age starts again.

Network issues are listed on the site's Network page and on the matched PC's page. They don't
yet get fix deadlines or exceptions like CVE and settings findings do.

## The agent side

`bw-agent sensor --out scan.json` runs one scan now, with no upload, and writes the payload. Use
it to check what a PC would report. See [agent/README.md](../agent/README.md).

`POST /api/agent/sensor` takes the gzip JSON scan from the site's sensor PC only. Any other PC
gets 409, which tells its agent to stop scanning until a heartbeat names it the sensor again.

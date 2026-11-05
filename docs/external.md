# Seen from the internet

What a client looks like from outside, checked once a week **without scanning anything**. A
technician lists the client's public IP addresses and domains on the client page (or
`bearwatch external add <client id> <address or domain>`).

| Target | Source | Becomes an issue |
|---|---|---|
| Public IP address | [Shodan InternetDB](https://internetdb.shodan.io), free and keyless: the ports Shodan's own crawlers saw open, and CVEs it matched to their banners | Remote Desktop, SMB, Telnet or VNC open to the internet (critical); databases, FTP, RPC and NetBIOS (high); CVEs Shodan matched (high if any are known exploited, else medium). A port first seen after the first check is marked **new** for a week. |
| Domain | DNS over HTTPS (Cloudflare), and one ordinary HTTPS connection to the website | No SPF, more than one SPF record, or SPF that allows any sender; no DMARC, more than one DMARC record, or DMARC that only monitors (a subdomain without its own record is judged by its parent's); DNSSEC off; website certificate expired or within two weeks of expiring |

- Cloudflare answers on about ten extra ports on every edge address. When an address shows
  those, they are dropped, so a site behind Cloudflare is not blamed for Cloudflare's ports.
- Shodan's CVE matches are guesses from banners. The issue says so; check the version on the
  device before acting.
- An issue closes when the next check no longer sees it. A check that fails (Shodan or DNS
  unreachable) changes nothing and shows the error on the client page.
- Shodan's data can be days old, so a port closed today may still show for a while.

## The client report

Two checklist items come from this:

- **Remote access and file sharing are closed to the internet:** fails if RDP, SMB, Telnet, VNC,
  RPC or NetBIOS is open on a listed address.
- **Email is protected from spoofing (SPF and DMARC):** fails if a listed domain lacks SPF or
  DMARC, has more than one SPF or DMARC record, or its SPF allows any sender.

With no addresses or domains listed, both say "Not yet".

## Not included: active scanning

Port sweeps, web scanning and nuclei templates send traffic to the client's network. That needs
the client's written permission, a scanning container on the server, and a decision about which
targets are in scope. It is left for a later change.

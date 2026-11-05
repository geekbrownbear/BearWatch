# Monthly client report

A short PDF for a QBR or a cyber insurance renewal: two or three US Letter pages, in the
Bearium light print palette. Everything in it comes from data BearWatch already has.

- **Dashboard:** the client page links to a browser preview and a PDF download. Both default to
  last month; add `?month=2026-10` for another one.
- **Command line:** `bearwatch report <client id> --out report.pdf [--month 2026-10] [--html]`.

The report describes the state on the day it is made: open problems, PCs, settings and network
as they are now. "Fixed in October" and the trend chart come from the found, fixed and
reopened events, so they show what happened in each month.

## What is in it

1. **Grade and key numbers.** PCs watched, problems fixed this month, the share fixed on time,
   updates for vulnerabilities attackers are using, updates past their deadline, and the total
   still to do.
2. **How the grade was set.** Every deduction, in words.
3. **Six months of progress.** Problems found and fixed each month, and how many were open at
   the end of each month (replayed from the events).
4. **The five most important things to do,** by risk score (see [scoring.md](scoring.md)).
5. **Cyber insurance checklist.** Questions most insurers ask, each answered from what BearWatch
   measured. An item BearWatch could not measure says "Not yet", never "Yes":
   - Antivirus is on and up to date (workstations), Windows Firewall is on, Remote Desktop
     requires sign-in first, SMBv1 is off, local admin passwords use LAPS. These come from the
     posture checks ([posture.md](posture.md)); PCs whose agent has not sent settings yet are
     not counted as passing.
   - Every PC runs a supported Windows version (see below).
   - Known exploited vulnerabilities are fixed within 14 days.
   - Every PC is monitored (checked in within 24 hours).
   - No unsafe services on the office network (needs the network sensor, [sensor.md](sensor.md)).
   - Remote access and file sharing closed to the internet, and email protected from spoofing
     (needs the client's public addresses and domains, [external.md](external.md)).
6. **Windows versions** and when each stops getting security updates.
7. **Risky Windows settings,** by how many PCs fail each one.
8. **The office network:** devices seen, devices without the agent, new devices, unsafe
   services, and the list of those services with how to fix them.

## The grade

It starts at 100 and loses points for specific problems. Each kind of problem has a cap, so one
bad month can't hide everything else.

| Problem | Points each | Most in total |
|---|---|---|
| An update not installed that fixes a known exploited vulnerability | 15 | 45 |
| An update past its fix deadline | 5 | 25 |
| A PC on a Windows version that no longer gets security updates | 5 | 15 |
| An insurance checklist item not met (other than the rows above and silent PCs) | 5 | 30 |
| A PC whose agent has not checked in for a day | 2 | 10 |

A is 90 or more, B 80, C 70, D 60, and F below 60. Counting is per update (per fix row), not per
CVE: one missing cumulative update that closes 40 CVEs costs the same as one that closes 2,
because it is one thing to do.

## Windows support dates

[`intel/windows_lifecycle.toml`](../intel/windows_lifecycle.toml) lists each Windows version by
build number, with Microsoft's end of updates date. Client versions have two dates: Home and Pro,
and Enterprise and Education. The report and the device page use it.

- A build that is not listed is "support date unknown", never "supported". Add each new Windows
  version when it ships.
- An unlisted Windows 10 build counts as out of support once the next listed Windows 10 release
  is, since older releases always end first.
- LTSC and LTSB editions have their own, much longer dates, so they show as unknown.
- Paid Extended Security Updates are not tracked. A PC on ESU still shows as out of support;
  record an exception if needed.

## PDF rendering

The server image includes WeasyPrint and the Pango libraries it needs. Fonts (Inter and Mozilla
Text) and the logo load from `bearwatch/web/static` on disk, so rendering needs no network. If
WeasyPrint is missing, the PDF link answers 503 and the HTML preview still works.

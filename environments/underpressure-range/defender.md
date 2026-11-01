# Underpressure Regional Water Authority — defender briefing

You are defending a replica of the Underpressure Regional Water Authority
environment: ten competition machines reached through their public VIPs
(172.25.31.0/24 → 172.20.240.0/24 via the edge router), one shared active
range for the whole team.

## What you control

| Host | Address (inside LAN) | Expected service |
| --- | --- | --- |
| ad-dns | 172.20.240.100 | Active Directory + DNS for underpressure.local |
| mssql | 172.20.240.120 | SQL Server hosting the store and webmail databases |
| ecomm | 172.20.240.10 | nginx + .NET store (aliases shop/store/www) |
| webmail | 172.20.240.15 | Postfix, Dovecot, Roundcube (mail.underpressure.local) |
| splunk | 172.20.240.20 | Splunk search head (edge syslog + workstation forwarder) |
| ubuntu-wkst | DHCP reservation .112 | workstation with a Splunk forwarder |
| win11-wkst | DHCP reservation .113 | domain-joined Windows workstation |
| team-kali | 172.17.0.2 (team segment) | your tooling VM |
| vyos-edge | routing | edge router holding the public NAT rules |
| perimeter firewall | .254 / 172.16.0.1 | substitute firewall (see caveats) |

Guest logins use the disposable lab credentials your captain distributes —
they are lab-generated, never platform accounts, and rotating them is a
valid defensive move (tell your captain if practice scoring depends on a
service account you rotated).

## Known starting weaknesses (deliberate)

The opening state intentionally reproduces the reported configuration:
permissive perimeter policy, unencrypted HTTP remote management on the
domain controller with relaxed client settings, Defender disabled there,
over-privileged account/group patterns and service accounts, readable
certificate-authority private material on the directory host, webmail with
relaxed TLS verification and its application database exposed through the
same SQL server, identity-service differences between Linux hosts, and
socket-activated SSH on the Linux workstation tier. Fix what you can,
keep services running, and watch the telemetry.

## How scoring is presented

Availability is measured from an external vantage through the public
paths using real transactions (catalogue traffic, mail send+retrieve,
directory queries, database reads, searchable ingest) — a stopped service
or an app that renders errors costs availability; a dependency outage is
recorded as unknown infrastructure, never silently as downtime or free
points. These are PRACTICE checks: the official competition rubric was
never supplied and no official weights are claimed.

## Timing, resets, recovery

This is a persistent lab: closing your browser, an idle evening, or an
optional exercise timer finishing never erases disks. Ending an exercise
stops scored runs and finalizes its evidence; the machines keep whatever
state you left. Only your captain can reset a machine (with an explicit
dependency impact preview — resetting the domain controller or the SQL
server affects everything downstream) or delete the lab. Power-off keeps
disks. Any active teammate can trigger emergency stop of offensive
activity; only the captain releases it. If you break SSH/firewall/WinRM
on a machine, the browser console still gets you in.

## Honest caveats

This is a labeled reconstruction, not a byte-for-byte copy: the perimeter
firewall is an OPNsense substitute (no PAN-OS/App-ID features), the
Windows 11 workstation runs an Enterprise evaluation image, SQL Server is
a Developer-edition reconstruction, identities and business content are
synthetic fiction, and evaluation licenses expire — the platform shows
license health so an expired guest never pretends to be healthy. The
original incident artifacts (attacker tooling, keys, trojaned utilities)
are NOT part of your starting state and will not be restored for you.

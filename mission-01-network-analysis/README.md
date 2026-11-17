# Mission 01: Network Traffic Analysis (Wireshark)

A hands-on SOC L1 exercise. I analyzed a 5-minute packet capture from a small office network (`10.0.0.0/24`), found several attacks hidden in normal traffic, and wrote an incident ticket for L2.

> **Note:** `mission-01.pcap` is a **synthetic training capture** made for practice. All IPs and domains are fake. This is not a real incident.

## What I did
- Opened the capture in Wireshark and mapped who talks to whom (**Statistics > Conversations / Endpoints**).
- Separated normal traffic from suspicious behavior using display filters and **Follow TCP Stream**.
- Built a timeline with packet numbers and wrote an incident ticket (see [`INC-0001-ticket.md`](INC-0001-ticket.md)).

## Findings

| Phase | Packets | What I found |
|---|---|---|
| Cleartext credentials | 292, 294 | FTP login from `10.0.0.31` to `10.0.0.9` with the username and password in plain text (password masked in my notes) |
| Port scan | 299-442 | `203.0.113.50` scanned `10.0.0.5`. Ports 22, 80, 445 and 3389 were open |
| SSH brute force | 443-902 | 45 short SSH sessions of similar size, then one much bigger session. This is a probable successful login |
| DNS tunneling pattern | 903-982 | `10.0.0.23` sent 40 TXT queries with random subdomains (38-52 chars) of `t-sync-cdn.example`, about one every 7 seconds |
| SMB sweep | 983-1042 | `10.0.0.23` probed 57 internal hosts on port 445. Three answered (10.0.0.5, .9, .14) |

**Most urgent hosts:** `10.0.0.23` (active DNS tunneling and lateral movement) and `10.0.0.5` (probable SSH compromise).

## MITRE ATT&CK mapping (suggested)
- Port scan and SMB sweep: **T1046** Network Service Discovery
- SSH brute force: **T1110.001** Brute Force: Password Guessing
- DNS tunneling pattern: **T1071.004** Application Layer Protocol: DNS

## What I could not prove
- A successful SSH login (the traffic is encrypted and I had no auth logs)
- Data exfiltration or a C2 server
- Whether the SMB probes led to real access

## Lessons learned (my mistakes)
- **Direction matters.** The side that sends the first `SYN` is the client. I read a conversation table backwards and mixed up attacker and victim.
- **`tcp.flags.ack` is not `tcp.ack`.** The first is the ACK flag, the second is the acknowledgment number.
- **`RST, ACK` means a closed port. `SYN, ACK` means an open port.** Many `RST, ACK` on different ports is a scan, not failed logins.
- **A SYN flood hits one target. A sweep sends one SYN to many hosts.**
- **Say "probable" until the logs prove it.**

## Tools
Wireshark. Filters I used are in [`wireshark-filters.md`](wireshark-filters.md).

## Files
- `README.md`: this file
- `INC-0001-ticket.md`: the incident ticket I wrote for L2
- `wireshark-filters.md`: filters and what each one showed
- `mission-01.pcap`: the synthetic capture

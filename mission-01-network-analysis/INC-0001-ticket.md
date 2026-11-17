# Incident Ticket: External SSH brute force and suspected internal compromise

**Ticket ID:** INC-0001
**Analyst:** Guilherme Pigoso (L1)
**Date of analysis:** 2026-11-17
**Data source:** mission-01.pcap (1042 packets, about 5 min 27 s, synthetic training capture)

## 1. Summary
An external host (203.0.113.50) scanned 10.0.0.5 and then brute-forced SSH on it. The last SSH session is much bigger than the others, so a login probably worked. Internal host 10.0.0.23 sends DNS queries that look like DNS tunneling and then scans the internal network on port 445, which suggests it is compromised and trying lateral movement. Also, an FTP login between 10.0.0.31 and 10.0.0.9 sent the username and password in plain text.

## 2. Severity
**Critical.** Plain-text credentials are confirmed. Two hosts are probably compromised (10.0.0.5 and 10.0.0.23). The lateral movement is still happening at the end of the capture. If L2 finds no successful login on 10.0.0.5, this can be lowered to High.

## 3. Timeline (time = seconds from start of capture)
| Packets | Time | Event |
|---|---|---|
| 292 and 294 | 19.6 to 19.7 s | FTP login in plain text, 10.0.0.31 to 10.0.0.9 (230 Login successful) |
| 299 to 442 | 19.8 to 20.7 s | Port scan from 203.0.113.50 against 10.0.0.5 |
| 443 to 902 | 20.8 to 55.1 s | SSH brute force from 203.0.113.50 to 10.0.0.5:22 |
| 903 to 982 | 55.1 to 320.8 s | DNS queries from 10.0.0.23 to 10.0.0.2 (suspected tunneling) |
| 983 to 1042 | 325.8 to 326.7 s | SMB sweep from 10.0.0.23 to internal hosts on port 445 |

## 4. Affected assets
| Host | Role | Status |
|---|---|---|
| 10.0.0.5 | Server (ports 22, 80, 445, 3389 open) | Suspected compromised (probable SSH login), exposed by the scan |
| 10.0.0.23 | Internal host (role to be confirmed) | Suspected compromised (DNS tunneling pattern and SMB sweep) |
| 10.0.0.9 | FTP server | Exposed (svc_backup credential seen in clear), answered the SMB sweep |
| 10.0.0.31 | Internal host, FTP client | Exposed (sent credentials in plain text) |
| 10.0.0.14 | Internal host (role to be confirmed) | Exposed (answered the SMB sweep, no sign of compromise) |
| 10.0.0.2 | DNS server | Received the suspicious queries, useful log source |

## 5. Indicators of Compromise (IOCs)
- External IP: 203.0.113.50
- Domain: t-sync-cdn.example (40 TXT queries, random subdomains of 38 to 52 characters, about one every 7 seconds)
- Internal source of suspicious traffic: 10.0.0.23
- Account exposed: svc_backup (password masked)
- Ports: 21, 22, 53, 445 (3389 and 80 were also found open)

## 6. Evidence
- **FTP in plain text:** packets 292 and 294. Filter: `ftp` or `tcp.port==21`. Username and password visible, server answered "230 Login successful".
- **Port scan:** packets 299 to 442. Filters: `ip.src==203.0.113.50` and `tcp.flags.reset==1`. Many different ports got RST, ACK (closed). Ports 22, 80, 445 and 3389 answered SYN, ACK (open).
- **SSH brute force:** packets 443 to 902. Filter: `ip.src==10.0.0.5 && ip.dst==203.0.113.50 && tcp.flags.reset==1`. 45 short sessions of about the same size, then one last session of about 4 KB (the others are about 640 bytes).
- **DNS tunneling pattern:** packets 903 to 982. Filter: `dns.qry.name contains "t-sync-cdn"`. 40 TXT queries and 40 answers, regular interval, random subdomains.
- **SMB sweep:** packets 983 to 1042. Filter: `ip.src==10.0.0.23 && tcp.dstport==445`. 57 hosts probed with one SYN each. 10.0.0.5, 10.0.0.9 and 10.0.0.14 answered SYN, ACK. No final ACK.

## 7. Assessment
- **Confirmed:** FTP credentials in plain text with a successful login. Port scan from 203.0.113.50. 45 short SSH connections. SMB sweep from 10.0.0.23.
- **Probable:** Successful SSH login on 10.0.0.5. DNS tunneling or beaconing from 10.0.0.23. Compromise of 10.0.0.23 and an attempt at lateral movement.
- **Cannot be proven with this capture:** The SSH login (traffic is encrypted, no auth logs). Data exfiltration. A C2 server. What the DNS queries carry. Whether the SMB probes led to any access.

## 8. Recommended actions
- **Immediate:** Isolate 10.0.0.23 and 10.0.0.5 from the network (do not power them off, keep the evidence). Disable or reset svc_backup. Block 203.0.113.50 at the firewall and block t-sync-cdn.example at DNS.
- **Short term:** Check /var/log/auth.log on 10.0.0.5 (Failed password followed by Accepted password). Search other logs for activity from 10.0.0.23 and for the domain. Check 10.0.0.9 and 10.0.0.14 for SMB logins. Check where svc_backup is used.
- **Long term:** Do not expose ports 22, 445 and 3389 to the internet (use a VPN). Add MFA and account lockout. Replace FTP with SFTP or FTPS. Segment the network and monitor DNS.

## 9. Escalation
**Escalated to:** L2 / Incident Response
**Reason:** Probable compromise of two hosts and active lateral movement.
**Next steps for L2:** Confirm the SSH login in the logs of 10.0.0.5. Investigate 10.0.0.23 (process, persistence, other connections). Decide on containment and on rotating svc_backup.

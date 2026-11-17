# Wireshark filters used

| Goal | Filter | What it showed |
|---|---|---|
| Handshake start only | `tcp.flags.syn==1 && tcp.flags.ack==0` | The first SYN of each connection |
| Open ports | `tcp.flags.syn==1 && tcp.flags.ack==1 && ip.addr==203.0.113.50` | Ports that answered SYN, ACK (22, 80, 445, 3389) |
| Closed ports | `tcp.flags.reset==1` | RST, ACK from many different ports (scan) |
| SSH brute force | `ip.src==10.0.0.5 && ip.dst==203.0.113.50 && tcp.flags.reset==1` | 45 short sessions, then a bigger one |
| Cleartext FTP | `ftp` or `tcp.port==21` | Username and password in plain text |
| DNS tunneling pattern | `dns.qry.name contains "t-sync-cdn"` | 40 TXT queries with random subdomains |
| SMB sweep | `ip.src==10.0.0.23 && tcp.dstport==445` | One SYN to 57 hosts, 3 answers |

## Menus I used
- **Statistics > Capture File Properties:** packet count and duration
- **Statistics > Conversations / Endpoints:** who talks to whom (check the SYN to see who started it)
- **Follow > TCP Stream:** read a full conversation

## Reminders
- `tcp.flags.ack == 1` is the ACK flag. `tcp.ack` is the acknowledgment number.
- The sender of the first SYN is the client.

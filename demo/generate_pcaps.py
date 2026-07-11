from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest
import random

def random_ip(): return f"192.168.1.{random.randint(2,50)}"
def server_ip(): return f"93.184.{random.randint(1,254)}.{random.randint(1,254)}"

# ── 1. NORMAL TRAFFIC ────────────────────────────────────────
def gen_normal():
    pkts = []
    sites = ["google.com", "github.com", "youtube.com", "stackoverflow.com"]
    for i in range(80):
        src = random_ip()
        dst = server_ip()
        sport = random.randint(1024, 65535)

        # HTTP GET
        http = (Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=80, flags="PA")/
                Raw(load=f"GET / HTTP/1.1\r\nHost: {random.choice(sites)}\r\nUser-Agent: Mozilla/5.0\r\n\r\n"))
        pkts.append(http)

        # DNS query
        dns = (Ether()/IP(src=src, dst="8.8.8.8")/UDP(sport=sport, dport=53)/
               DNS(rd=1, qd=DNSQR(qname=random.choice(sites))))
        pkts.append(dns)

        # TLS (simulated - just the record header)
        tls_hello = bytes([0x16, 0x03, 0x01, 0x00, 0x05])
        tls = (Ether()/IP(src=src, dst=dst)/TCP(sport=sport, dport=443, flags="PA")/
               Raw(load=tls_hello))
        pkts.append(tls)

    wrpcap("demo/normal_traffic.pcap", pkts)
    print(f"[+] normal_traffic.pcap — {len(pkts)} packets")

# ── 2. PORT SCAN ─────────────────────────────────────────────
def gen_port_scan():
    pkts = []
    attacker = "10.0.0.99"
    target   = "192.168.1.10"
    # SYN scan across 30 ports (classic Nmap behavior)
    ports = [21,22,23,25,53,80,110,135,139,143,443,445,
             993,995,1433,1521,3306,3389,5432,5900,
             6379,8080,8443,8888,9200,27017,
             4444,4445,4446,4447]
    for port in ports:
        syn = (Ether()/IP(src=attacker, dst=target)/
               TCP(sport=random.randint(40000,60000), dport=port, flags="S"))
        pkts.append(syn)
        # Some ports respond RST (closed)
        if port not in [80, 443, 22]:
            rst = (Ether()/IP(src=target, dst=attacker)/
                   TCP(sport=port, dport=syn[TCP].sport, flags="RA"))
            pkts.append(rst)

    wrpcap("demo/port_scan.pcap", pkts)
    print(f"[+] port_scan.pcap — {len(pkts)} packets")

# ── 3. SQL INJECTION ─────────────────────────────────────────
def gen_sql_injection():
    pkts = []
    attacker = "10.0.0.55"
    server   = "192.168.1.20"

    payloads = [
        "POST /login HTTP/1.1\r\nHost: victim.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nuser=' OR '1'='1&pass=anything",
        "GET /search?q=1 UNION SELECT username,password FROM users-- HTTP/1.1\r\nHost: victim.com\r\n\r\n",
        "POST /api/data HTTP/1.1\r\nHost: victim.com\r\nContent-Type: application/json\r\n\r\n{\"id\": \"1; DROP TABLE users--\"}",
        "GET /page?id=1' AND SLEEP(5)-- HTTP/1.1\r\nHost: victim.com\r\n\r\n",
        "POST /comment HTTP/1.1\r\nHost: victim.com\r\n\r\nbody=<script>alert(1)</script>",
        "GET /admin?user=admin'-- HTTP/1.1\r\nHost: victim.com\r\n\r\n",
    ]

    # Normal requests first (baseline)
    for i in range(20):
        normal = (Ether()/IP(src=attacker, dst=server)/
                  TCP(sport=random.randint(1024,65535), dport=80, flags="PA")/
                  Raw(load=f"GET /page/{i} HTTP/1.1\r\nHost: victim.com\r\n\r\n"))
        pkts.append(normal)

    # Then attack payloads
    for payload in payloads:
        pkt = (Ether()/IP(src=attacker, dst=server)/
               TCP(sport=random.randint(1024,65535), dport=80, flags="PA")/
               Raw(load=payload))
        pkts.append(pkt)

    wrpcap("demo/sql_injection.pcap", pkts)
    print(f"[+] sql_injection.pcap — {len(pkts)} packets")

# ── 4. DATA EXFILTRATION ─────────────────────────────────────
def gen_exfiltration():
    pkts = []
    insider  = "192.168.1.42"
    foreign  = "185.220.101.55"  # Tor exit node range

    # Normal daytime traffic first (build baseline feel)
    for i in range(20):
        normal = (Ether()/IP(src=insider, dst="8.8.8.8")/
                  UDP(sport=random.randint(1024,65535), dport=53)/
                  DNS(rd=1, qd=DNSQR(qname="google.com")))
        pkts.append(normal)

    # Then large upload at unusual port (exfiltration)
    chunk = b"EXFIL:" + b"A" * 1400  # large payload chunks
    for i in range(60):  # 60 chunks = ~84KB total
        pkt = (Ether()/IP(src=insider, dst=foreign)/
               TCP(sport=random.randint(1024,65535), dport=4444, flags="PA")/
               Raw(load=chunk))
        pkts.append(pkt)

    wrpcap("demo/exfiltration.pcap", pkts)
    print(f"[+] exfiltration.pcap — {len(pkts)} packets")

# ── Run all ──────────────────────────────────────────────────
if __name__ == "__main__":
    gen_normal()
    gen_port_scan()
    gen_sql_injection()
    gen_exfiltration()
    print("\n✅ All pcap files generated in demo/")

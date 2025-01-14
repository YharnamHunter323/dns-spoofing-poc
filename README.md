# DNS Spoofing Proof of Concept

This repository demonstrates a DNS spoofing attack in a controlled test environment using Python and Scapy.

## Setup Requirements

- 3 Virtual Machines:
  - Ubuntu Server (192.168.100.10)
  - Kali Linux - Attacker (192.168.100.20)
  - Ubuntu Desktop - Victim (192.168.100.30)
- VirtualBox with NAT Network
- Python3
- Scapy library

## Network Configuration

All machines are connected to a NAT Network (192.168.100.0/24) with:
- Server: 192.168.100.10
- Attacker: 192.168.100.20
- Victim: 192.168.100.30

## Attack Implementation

The attack uses Python with Scapy to:
1. Intercept DNS queries
2. Generate spoofed responses
3. Redirect traffic to our controlled server

## Running the Attack

1. Set up network configuration
2. Start Apache on server
3. Run DNS spoofing script on attacker
4. Test from victim machine

## Warning

This code is for educational purposes only. Use only in controlled test environments.

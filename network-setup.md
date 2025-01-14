# Network Setup Guide for DNS Spoofing POC

## VirtualBox Network Configuration

1. Create NAT Network
   - Name: DNSTEST
   - Network CIDR: 192.168.100.0/24
   - Disable DHCP

2. Configure VMs Network Adapters
   - Adapter 1: NAT Network "DNSTEST"
   - Promiscuous Mode: Allow All
   - Cable Connected: Yes

## Machine Configurations

### Ubuntu Server (Target Redirection)
- IP: 192.168.100.10
- Install and configure Apache2:
```bash
sudo apt update
sudo apt install apache2
```

### Kali Linux (Attacker)
- IP: 192.168.100.20
- Required packages:
```bash
sudo apt install python3-scapy
```
- Enable IP forwarding:
```bash
sudo sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'
```

### Ubuntu Desktop (Victim)
- IP: 192.168.100.30
- Configure static networking:
```yaml
# /etc/netplan/00-installer-config.yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3:
      addresses:
        - 192.168.100.30/24
      routes:
        - to: default
          via: 192.168.100.1
      nameservers:
        addresses: [192.168.100.20]
      dhcp4: no
```

Apply network configuration:
```bash
sudo netplan apply
```

## Testing Configuration

1. Verify connectivity between machines:
```bash
ping 192.168.100.10  # Server
ping 192.168.100.20  # Attacker
ping 192.168.100.30  # Victim
```

2. Verify DNS resolution on victim:
```bash
nslookup example.com
```

3. Verify Apache is running on server:
```bash
curl http://192.168.100.10
```

## Troubleshooting

Common issues and solutions:

### DNS Resolution Fails
1. Check netplan configuration
2. Verify DNS spoofing script is running
3. Check IP forwarding is enabled
4. Verify Apache is running

### Web Access Fails
1. Check Apache status:
```bash
sudo systemctl status apache2
```
2. Verify firewall settings:
```bash
sudo ufw status
```
3. Check Apache error logs:
```bash
sudo tail -f /var/log/apache2/error.log
```

### Connection Issues
1. Verify all machines are on correct network
2. Check IP addresses are correctly assigned
3. Ensure Promiscuous Mode is enabled in VirtualBox
4. Verify no IP conflicts exist

## Security Note

This setup is for educational purposes only and should only be used in a controlled test environment. Never attempt DNS spoofing on production networks or without explicit authorization.
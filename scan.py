import csv
import socket
import time
import requests
import threading
import struct
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import *
from getmac import get_mac_address
from ipwhois import IPWhois
from netaddr import IPNetwork
from mac_vendor_lookup import MacLookup
import json
from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress
import subprocess
import platform
import random
import os


class AdvancedOTScanner:
    def __init__(self, shodan_api_key=None):
        self.shodan_api_key = shodan_api_key
        self.console = Console()
        # Suppress Scapy warnings and verbose output
        conf.verb = 0
        conf.checkIPaddr = False
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy").setLevel(logging.ERROR)

        try:
            MacLookup().update_vendors()
        except:
            pass

        # Advanced OT protocol definitions with multiple detection methods
        self.OT_PROTOCOLS = {
            "modbus": {
                "ports": [502, 802],
                "tcp_probe": self._create_modbus_probe(),
                "signatures": [
                    b"\x00\x00\x00\x00\x00\x03\x01\x83",  # Exception response
                    b"\x00\x00\x00\x00\x00\x05\x01\x03",  # Read response
                    b"modbus", b"MODBUS"
                ],
                "banner_keywords": ["modbus", "schneider", "unitronics"]
            },
            "bacnet": {
                "ports": [47808],
                "udp_probe": self._create_bacnet_probe(),
                "signatures": [
                    b"\x81\x0b\x00",  # BACnet response
                    b"bacnet", b"BACnet"
                ],
                "banner_keywords": ["bacnet", "johnson controls", "honeywell"]
            },
            "opcua": {
                "ports": [4840],
                "tcp_probe": self._create_opcua_probe(),
                "signatures": [
                    b"ACK\x00",  # OPC UA ACK
                    b"HEL\x00",  # OPC UA Hello
                    b"opcua", b"OPC"
                ],
                "banner_keywords": ["opcua", "opc ua", "prosys"]
            },
            "dnp3": {
                "ports": [20000, 19999],
                "tcp_probe": self._create_dnp3_probe(),
                "signatures": [
                    b"\x05\x64",  # DNP3 start bytes
                    b"dnp", b"DNP"
                ],
                "banner_keywords": ["dnp3", "triangle microworks"]
            },
            "mqtt": {
                "ports": [1883, 8883],
                "tcp_probe": self._create_mqtt_probe(),
                "signatures": [
                    b"\x20\x02\x00\x00",  # CONNACK
                    b"mqtt", b"MQTT"
                ],
                "banner_keywords": ["mqtt", "mosquitto", "hivemq"]
            },
            "siemens_s7": {
                "ports": [102],
                "tcp_probe": self._create_s7_probe(),
                "signatures": [
                    b"\x03\x00\x00\x1b\x02\xf0\x80",  # S7 response
                    b"siemens", b"s7"
                ],
                "banner_keywords": ["siemens", "s7", "step7"]
            },
            "ethernet_ip": {
                "ports": [44818, 2222],
                "tcp_probe": self._create_enip_probe(),
                "signatures": [
                    b"\x00\x00\x00\x00",  # EtherNet/IP response
                    b"rockwell", b"allen"
                ],
                "banner_keywords": ["ethernet/ip", "rockwell", "allen bradley"]
            },
            "omron_fins": {
                "ports": [9600],
                "tcp_probe": self._create_fins_probe(),
                "signatures": [
                    b"FINS", b"omron"
                ],
                "banner_keywords": ["omron", "fins"]
            },
            "codesys": {
                "ports": [2455, 1217],
                "tcp_probe": b"\x01\x00\x00\x00",
                "signatures": [
                    b"codesys", b"3s"
                ],
                "banner_keywords": ["codesys", "3s-smart"]
            }
        }

        # Comprehensive port list
        self.OT_PORTS = [
            # Modbus
            502, 802,
            # BACnet
            47808,
            # OPC UA
            4840,
            # DNP3
            20000, 19999,
            # MQTT
            1883, 8883,
            # Siemens S7
            102,
            # EtherNet/IP
            44818, 2222,
            # Other OT protocols
            789, 1089, 1911, 2404, 4000, 5020, 9600,
            34962, 34963, 34964, 2455, 1217,
            # Common services that might run on OT devices
            21, 22, 23, 25, 53, 80, 135, 139, 443, 445,
            993, 995, 1433, 3389, 5900, 6379, 8080, 8443
        ]

    def _create_modbus_probe(self):
        """Create Modbus TCP probe packet"""
        # Transaction ID + Protocol ID + Length + Unit ID + Function Code + Starting Address + Quantity
        return b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"

    def _create_bacnet_probe(self):
        """Create BACnet Who-Is probe"""
        return b"\x81\x0a\x00\x08\x01\x20\xff\xff\x00\xff\x10\x08"

    def _create_opcua_probe(self):
        """Create OPC UA Hello message"""
        hello = b"HEL" + b"F" + struct.pack("<I", 28) + struct.pack("<I", 0) + struct.pack("<I", 65536) + struct.pack(
            "<I", 65536) + struct.pack("<I", 0) + b"opc.tcp://test/"
        return hello[:28]  # Truncate to proper length

    def _create_dnp3_probe(self):
        """Create DNP3 link layer frame"""
        return b"\x05\x64\x05\xc0\x01\x00\x00\x04\xe9\x21"

    def _create_mqtt_probe(self):
        """Create MQTT CONNECT packet"""
        return b"\x10\x0e\x00\x04MQTT\x04\x00\x00\x3c\x00\x04test"

    def _create_s7_probe(self):
        """Create Siemens S7 COTP connection request"""
        return b"\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x0a"

    def _create_enip_probe(self):
        """Create EtherNet/IP list services request"""
        return b"\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    def _create_fins_probe(self):
        """Create Omron FINS probe"""
        return b"\x46\x49\x4e\x53\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"

    def advanced_arp_scan(self, subnet):
        """Advanced ARP scan with multiple techniques and better error handling"""
        hosts = []

        # Method 1: Scapy ARP scan with improved handling
        try:
            self.console.print("[blue]Running ARP scan...[/blue]")

            # Get network interface info for better routing
            network = IPNetwork(subnet)

            # Create ARP request with explicit interface handling
            arp = ARP(pdst=subnet)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            # Suppress warnings during scan
            old_verb = conf.verb
            conf.verb = 0

            try:
                # Use srp1 with specific parameters to reduce warnings
                answered, _ = srp(packet, timeout=2, verbose=False, retry=2, inter=0.1)

                for _, rcv in answered:
                    mac = rcv.hwsrc
                    ip = rcv.psrc
                    try:
                        vendor = MacLookup().lookup(mac)
                    except:
                        vendor = "Unknown"
                    hosts.append({'ip': ip, 'mac': mac, 'vendor': vendor})

            finally:
                conf.verb = old_verb

        except Exception as e:
            self.console.print(
                f"[yellow]ARP scan encountered issues (continuing with other methods): {str(e)[:50]}...[/yellow]")

        # Method 2: Enhanced ping sweep
        try:
            self.console.print("[blue]Running ping sweep...[/blue]")
            network = IPNetwork(subnet)
            ping_hosts = self._ping_sweep(network)

            # Add safety check
            if ping_hosts is None:
                ping_hosts = []

            # Merge results and get MAC addresses
            existing_ips = {host['ip'] for host in hosts}
            for ip in ping_hosts:
                if ip not in existing_ips:
                    mac = "Unknown"
                    vendor = "Unknown"

                    # Try to get MAC address using different methods
                    try:
                        # Method 1: getmac library
                        mac = get_mac_address(ip=ip)
                        if not mac:
                            # Method 2: ARP table lookup
                            mac = self._get_mac_from_arp_table(ip)

                        if mac and mac != "Unknown":
                            try:
                                vendor = MacLookup().lookup(mac)
                            except:
                                vendor = "Unknown"
                    except:
                        pass

                    hosts.append({'ip': ip, 'mac': mac or 'Unknown', 'vendor': vendor})

        except Exception as e:
            self.console.print(f"[yellow]Ping sweep failed: {e}[/yellow]")

        # Method 3: Fallback - direct IP range scan for critical OT ports
        if len(hosts) < 5:  # If we didn't find many hosts, try direct scanning
            try:
                self.console.print("[blue]Running direct port probe for host discovery...[/blue]")
                network = IPNetwork(subnet)
                critical_ports = [80, 443, 22, 23, 502, 102, 44818, 47808]  # Mix of common and OT ports

                additional_hosts = self._direct_port_discovery(network, critical_ports)
                existing_ips = {host['ip'] for host in hosts}

                for ip in additional_hosts:
                    if ip not in existing_ips:
                        hosts.append({'ip': ip, 'mac': 'Unknown', 'vendor': 'Unknown'})

            except Exception as e:
                self.console.print(f"[yellow]Direct port discovery failed: {e}[/yellow]")

        return hosts

    def _ping_sweep(self, network):
        """Perform ping sweep"""
        alive_hosts = []
        hosts_to_ping = list(network.iter_hosts())[:254]  # Limit to prevent overwhelming

        def ping_host(ip):
            try:
                if platform.system().lower() == "windows":
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)],
                                            capture_output=True, text=True, timeout=2)
                else:
                    result = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)],
                                            capture_output=True, text=True, timeout=2)
                return str(ip) if result.returncode == 0 else None
            except:
                return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = {executor.submit(ping_host, ip): ip for ip in hosts_to_ping}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)

        # FIXED: Added missing return statement
        return alive_hosts

    def _get_mac_from_arp_table(self, ip):
        """Get MAC address from system ARP table"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['arp', '-a', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if '-' in part and len(part) == 17:  # MAC format
                                    return part.replace('-', ':')
            else:
                result = subprocess.run(['arp', '-n', ip], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    for line in lines:
                        if ip in line:
                            parts = line.split()
                            for part in parts:
                                if ':' in part and len(part) == 17:  # MAC format
                                    return part
        except:
            pass
        return None

    def _direct_port_discovery(self, network, ports):
        """Direct port probing for host discovery"""
        alive_hosts = []
        hosts_to_check = list(network.iter_hosts())[:100]  # Limit scope

        def check_host_port(ip):
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((str(ip), port))
                    sock.close()
                    if result == 0:
                        return str(ip)
                except:
                    continue
            return None

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_host_port, ip): ip for ip in hosts_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive_hosts.append(result)

        return alive_hosts

    def advanced_port_scan(self, ip, ports, timeout=1):
        """Multi-method port scanning"""
        open_ports = []

        # Method 1: TCP Connect scan (most reliable)
        tcp_ports = self._tcp_connect_scan(ip, ports, timeout)
        open_ports.extend(tcp_ports)

        # Method 2: SYN scan for stealth (if scapy available)
        try:
            syn_ports = self._syn_scan(ip, ports, timeout)
            # Merge unique ports
            for port in syn_ports:
                if port not in open_ports:
                    open_ports.append(port)
        except:
            pass

        return sorted(list(set(open_ports)))

    def _tcp_connect_scan(self, ip, ports, timeout):
        """Enhanced TCP connect scan"""
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    # Try to grab banner
                    try:
                        sock.settimeout(0.5)
                        banner = sock.recv(1024)
                        sock.close()
                        return (port, banner)
                    except:
                        sock.close()
                        return (port, b"")
                sock.close()
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result[0])

        return open_ports

    def _syn_scan(self, ip, ports, timeout):
        """SYN scan using scapy with better error handling"""
        open_ports = []
        try:
            # Suppress Scapy warnings during SYN scan
            old_verb = conf.verb
            conf.verb = 0

            # Limit ports to prevent overwhelming the network
            ports_to_scan = ports[:50] if len(ports) > 50 else ports

            # Create SYN packets with random source port
            src_port = random.randint(1024, 65535)
            responses = sr(IP(dst=ip) / TCP(sport=src_port, dport=ports_to_scan, flags="S"),
                           timeout=timeout, verbose=False, retry=1)[0]

            for sent, received in responses:
                if received.haslayer(TCP) and received[TCP].flags == 18:  # SYN-ACK
                    open_ports.append(received[TCP].sport)
                    # Send RST to close connection cleanly
                    try:
                        send(IP(dst=ip) / TCP(sport=src_port, dport=received[TCP].sport, flags="R"),
                             verbose=False)
                    except:
                        pass

            conf.verb = old_verb

        except Exception as e:
            # SYN scan failed, that's okay - we have TCP connect as backup
            pass

        return open_ports

    def advanced_protocol_detection(self, ip, port, timeout=3):
        """Advanced protocol detection with multiple methods"""
        detected = []

        # Method 1: Banner grabbing
        banner = self._grab_banner(ip, port, timeout)
        if banner:
            detected.extend(self._analyze_banner(banner, port))

        # Method 2: Active probing
        for protocol, config in self.OT_PROTOCOLS.items():
            if port in config["ports"]:
                result = self._probe_protocol(ip, port, protocol, config, timeout)
                if result and result not in detected:
                    detected.append(result)

        # Method 3: Service detection
        service = self._detect_service(ip, port)
        if service and service not in detected:
            detected.append(service)

        return detected

    def _grab_banner(self, ip, port, timeout):
        """Enhanced banner grabbing"""
        banners = []

        # Try different approaches
        approaches = [
            b"",  # Just connect
            b"\r\n",  # HTTP-like
            b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n",  # HTTP
            b"\x00" * 4,  # Null bytes
        ]

        for approach in approaches:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((ip, port))

                if approach:
                    sock.send(approach)
                    time.sleep(0.1)

                banner = sock.recv(4096)
                sock.close()

                if banner and len(banner) > 0:
                    banners.append(banner)
                    break
            except:
                continue

        return banners[0] if banners else b""

    def _analyze_banner(self, banner, port):
        """Analyze banner for protocol signatures"""
        detected = []
        banner_lower = banner.lower()
        banner_str = banner.decode('utf-8', errors='ignore').lower()

        for protocol, config in self.OT_PROTOCOLS.items():
            # Check binary signatures
            for sig in config.get("signatures", []):
                if sig.lower() in banner_lower:
                    detected.append(protocol)
                    break

            # Check keyword signatures
            for keyword in config.get("banner_keywords", []):
                if keyword.lower() in banner_str:
                    if protocol not in detected:
                        detected.append(protocol)
                    break

        return detected

    def _probe_protocol(self, ip, port, protocol, config, timeout):
        """Send protocol-specific probes"""
        try:
            if "tcp_probe" in config:
                return self._tcp_probe(ip, port, protocol, config["tcp_probe"], config.get("signatures", []), timeout)
            elif "udp_probe" in config:
                return self._udp_probe(ip, port, protocol, config["udp_probe"], config.get("signatures", []), timeout)
        except:
            pass
        return None

    def _tcp_probe(self, ip, port, protocol, probe, signatures, timeout):
        """Send TCP probe and analyze response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            sock.send(probe)
            response = sock.recv(4096)
            sock.close()

            if response:
                response_lower = response.lower()
                for sig in signatures:
                    if sig.lower() in response_lower:
                        return protocol

                # Check if we got any meaningful response (likely the right protocol)
                if len(response) > 4:
                    return f"{protocol}?"
        except:
            pass
        return None

    def _udp_probe(self, ip, port, protocol, probe, signatures, timeout):
        """Send UDP probe and analyze response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(probe, (ip, port))
            response, _ = sock.recvfrom(4096)
            sock.close()

            if response:
                response_lower = response.lower()
                for sig in signatures:
                    if sig.lower() in response_lower:
                        return protocol

                if len(response) > 4:
                    return f"{protocol}?"
        except:
            pass
        return None

    def _detect_service(self, ip, port):
        """Detect standard services"""
        try:
            service_name = socket.getservbyport(port)
            return f"service_{service_name}"
        except:
            return None

    def run_comprehensive_scan(self, subnet):
        """Run comprehensive scan with all methods"""
        results = []

        self.console.print(f"[bold blue]Starting comprehensive OT scan for {subnet}[/bold blue]")

        # Host discovery
        hosts = self.advanced_arp_scan(subnet)
        if not hosts:
            self.console.print("[red]No hosts discovered![/red]")
            return []

        self.console.print(f"[green]Discovered {len(hosts)} hosts[/green]")

        # Scan each host
        with Progress() as progress:
            task = progress.add_task("Comprehensive scanning...", total=len(hosts))

            for host in hosts:
                ip = host['ip']
                progress.update(task, description=f"Scanning {ip}")

                # Port scanning
                open_ports = self.advanced_port_scan(ip, self.OT_PORTS, timeout=1)

                # Protocol detection
                ot_services = []
                all_services = {}

                for port in open_ports:
                    protocols = self.advanced_protocol_detection(ip, port)
                    all_services[port] = protocols

                    for protocol in protocols:
                        if any(ot_keyword in protocol.lower() for ot_keyword in
                               ['modbus', 'bacnet', 'opcua', 'dnp3', 'mqtt', 's7', 'ethernet', 'fins', 'codesys']):
                            ot_services.append((port, protocol))

                # Shodan enrichment
                shodan_data = self.enrich_with_shodan(ip)

                results.append({
                    'ip': ip,
                    'mac': host['mac'],
                    'vendor': host['vendor'],
                    'ports': open_ports,
                    'ot_services': ot_services,
                    'all_services': all_services,
                    'shodan': shodan_data
                })

                progress.advance(task)

        return results

    def enrich_with_shodan(self, ip):
        """Shodan enrichment"""
        if not self.shodan_api_key:
            return {}

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_api_key}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except:
            pass
        return {}

    def display_results(self, results):
        """Enhanced results display"""
        # Main results table
        table = Table(title="Advanced OT Discovery Results")
        table.add_column("IP", style="cyan")
        table.add_column("MAC", style="blue")
        table.add_column("Vendor", style="green")
        table.add_column("Open Ports", style="yellow")
        table.add_column("OT Protocols", style="red", width=30)
        table.add_column("Risk", style="magenta")

        ot_devices = []

        for r in results:
            ports_str = ", ".join(map(str, r['ports'][:10]))  # Limit display
            if len(r['ports']) > 10:
                ports_str += "..."

            ot_str = ", ".join([f"{p}:{proto}" for p, proto in r['ot_services']])

            # Risk assessment
            risk = "Low"
            if r['ot_services']:
                if len(r['ot_services']) > 3:
                    risk = "Critical"
                elif len(r['ot_services']) > 1:
                    risk = "High"
                else:
                    risk = "Medium"
                ot_devices.append(r)

            table.add_row(r['ip'], r['mac'], r['vendor'], ports_str, ot_str, risk)

        self.console.print(table)

        # OT Device Summary
        if ot_devices:
            self.console.print(f"\n[bold red]🚨 DETECTED {len(ot_devices)} POTENTIAL OT/ICS DEVICES 🚨[/bold red]")

            ot_table = Table(title="OT Device Details")
            ot_table.add_column("IP", style="cyan")
            ot_table.add_column("Vendor", style="green")
            ot_table.add_column("Detected Protocols", style="red")
            ot_table.add_column("All Services", style="yellow")

            for device in ot_devices:
                protocols = [proto for _, proto in device['ot_services']]
                all_svcs = []
                for port, services in device['all_services'].items():
                    for svc in services:
                        all_svcs.append(f"{port}:{svc}")

                ot_table.add_row(
                    device['ip'],
                    device['vendor'],
                    ", ".join(protocols),
                    ", ".join(all_svcs[:5]) + ("..." if len(all_svcs) > 5 else "")
                )

            self.console.print(ot_table)

        # Statistics
        self.console.print(f"\n[blue]Scan Statistics:[/blue]")
        self.console.print(f"• Total hosts: {len(results)}")
        self.console.print(f"• Hosts with open ports: {len([r for r in results if r['ports']])}")
        self.console.print(f"• Potential OT devices: {len(ot_devices)}")

        if ot_devices:
            protocols_found = set()
            for device in ot_devices:
                for _, proto in device['ot_services']:
                    protocols_found.add(proto)
            self.console.print(f"• OT Protocols detected: {', '.join(sorted(protocols_found))}")

    def export_detailed_csv(self, results, filename="advanced_ot_scan.csv"):
        """Export detailed results"""
        with open(filename, "w", newline="", encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                "IP", "MAC", "Vendor", "Open Ports", "OT Services",
                "All Detected Services", "Risk Level", "Port Count", "OT Protocol Count"
            ])

            for r in results:
                risk = "Low"
                if r['ot_services']:
                    if len(r['ot_services']) > 3:
                        risk = "Critical"
                    elif len(r['ot_services']) > 1:
                        risk = "High"
                    else:
                        risk = "Medium"

                all_services = []
                for port, services in r['all_services'].items():
                    for svc in services:
                        all_services.append(f"{port}:{svc}")

                writer.writerow([
                    r['ip'], r['mac'], r['vendor'],
                    ";".join(map(str, r['ports'])),
                    ";".join([f"{p}:{proto}" for p, proto in r['ot_services']]),
                    ";".join(all_services),
                    risk,
                    len(r['ports']),
                    len(r['ot_services'])
                ])

        self.console.print(f"[green]Detailed results exported to {filename}[/green]")


if __name__ == "__main__":
    console = Console()
    console.print("[bold blue]Advanced OT/ICS Scanner v2.0[/bold blue]")
    console.print("Enhanced network handling and warning suppression.\n")

    # Check if running with appropriate privileges
    try:
        if platform.system().lower() != "windows":
            if os.geteuid() != 0:
                console.print("[yellow]⚠️  For best results, run as root/administrator for SYN scanning[/yellow]")
        else:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                console.print("[yellow]⚠️  For best results, run as administrator for advanced scanning[/yellow]")
    except:
        pass

    # Get API key
    api_key = input("Enter Shodan API key (optional, press Enter to skip): ").strip() or None

    # Get subnet with examples
    console.print("\n[blue]Examples:[/blue] 192.168.1.0/24, 10.0.0.0/16, 172.16.0.0/12")
    while True:
        subnet = input("Enter subnet to scan: ").strip()
        try:
            net = IPNetwork(subnet)
            if net.size > 1024:
                confirm = input(f"Large network ({net.size} hosts). Continue? (y/n): ")
                if confirm.lower() != 'y':
                    continue
            break
        except:
            print("Invalid subnet format! Use CIDR notation (e.g., 192.168.1.0/24)")

    # Scan options
    console.print("\n[blue]Scan Options:[/blue]")
    console.print("1. Quick scan (common ports only)")
    console.print("2. Full scan (all OT ports)")
    console.print("3. Stealth scan (slower, less detectable)")

    scan_type = input("Select scan type (1-3, default=2): ").strip() or "2"

    # Initialize scanner
    scanner = AdvancedOTScanner(shodan_api_key=api_key)

    # Adjust scan parameters based on choice
    if scan_type == "1":
        scanner.OT_PORTS = [21, 22, 23, 80, 443, 502, 102, 44818, 47808, 4840, 1883, 20000]
        console.print("[blue]Quick scan mode selected[/blue]")
    elif scan_type == "3":
        # Stealth mode - smaller concurrent threads, longer timeouts
        console.print("[blue]Stealth scan mode selected (this will take longer)[/blue]")

    console.print(f"\n[green]Starting scan of {subnet}...[/green]")

    # Run scan
    start_time = time.time()
    results = scanner.run_comprehensive_scan(subnet)
    end_time = time.time()

    if results:
        console.print(f"\n[green]Scan completed in {end_time - start_time:.1f} seconds[/green]")
        scanner.display_results(results)

        # Export options
        console.print("\n[blue]Export Options:[/blue]")
        export = input("Export results? (csv/json/both/no): ").lower().strip()
        if export in ['csv', 'both']:
            scanner.export_detailed_csv(results)
        if export in ['json', 'both']:
            with open("ot_scan_results.json", "w") as f:
                json.dump(results, f, indent=2, default=str)
            console.print("[green]JSON results exported to ot_scan_results.json[/green]")
    else:
        console.print("[red]No results obtained. Check network connectivity and permissions.[/red]")
        console.print("\n[yellow]Troubleshooting tips:[/yellow]")
        console.print("• Run as administrator/root")
        console.print("• Check if you're on the right network segment")
        console.print("• Try a smaller subnet (e.g., /28 instead of /24)")
        console.print("• Verify the subnet address is correct")
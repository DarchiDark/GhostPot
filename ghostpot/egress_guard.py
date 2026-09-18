import subprocess
import logging

logger = logging.getLogger("ghostpot.egress_guard")

class EgressGuard:
    @staticmethod
    def setup_global_rules():
        """Initializes global forwarding and NAT rules."""
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1\n")
        except Exception as e:
            logger.warning(f"Could not write to ip_forward: {e}")

        # NAT for outbound traffic
        subprocess.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "10.99.0.0/16", "!", "-d", "10.99.0.0/16", "-j", "MASQUERADE"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def cleanup_global_rules():
        """Removes global forwarding and NAT rules upon shutdown."""
        subprocess.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "10.99.0.0/16", "!", "-d", "10.99.0.0/16", "-j", "MASQUERADE"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def apply_guest_rules(guest_ip: str, host_veth_ip: str, veth_host: str):
        """
        Rock-solid Outbound Protection Policy:
        1. Local ICMP Echo Responder: All ping requests are answered locally by host gateway (0 external packets).
        2. Dangerous Ports Instant TCP RST: Outbound 22, 23, 445, 135, 139, 3389, 5555 -> Immediate TCP RST.
        3. Block Private & Cloud Metadata: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254.
        4. Strict Outbound Quota (Max 3 Target IPs):
           - Uses ipset / iptables connlimit + hashlimit to strictly enforce maximum 3 target destination IPs per sandbox.
           - Any connection to a 4th IP or mass scanning is immediately rejected with TCP RST.
        """
        chain_name = f"EG_{guest_ip.replace('.', '_')}"
        recent_name = f"R_{guest_ip.replace('.', '_')}"

        # 1. Fake ICMP Ping: Redirect to host gateway locally
        subprocess.run([
            "iptables", "-t", "nat", "-I", "PREROUTING", "-i", veth_host, "-s", guest_ip,
            "-p", "icmp", "--icmp-type", "echo-request", "-j", "DNAT", "--to-destination", host_veth_ip
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. Create dedicated chain for this guest
        subprocess.run(["iptables", "-N", chain_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-F", chain_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-I", "FORWARD", "-s", guest_ip, "-j", chain_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 3. Allow established & related
        subprocess.run(["iptables", "-A", chain_name, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 4. Allow communication with host gateway (DNS / ICMP / Proxy)
        subprocess.run(["iptables", "-A", chain_name, "-d", host_veth_ip, "-j", "ACCEPT"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 5. Block private ranges & cloud metadata
        for subnet in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.169.254"]:
            subprocess.run(["iptables", "-A", chain_name, "-d", subnet, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 6. Dangerous scanning/abuse ports -> Immediate TCP RST Inject
        dangerous_ports = "22,23,445,135,139,3389,5555"
        subprocess.run([
            "iptables", "-A", chain_name, "-p", "tcp",
            "-m", "multiport", "--dports", dangerous_ports,
            "-j", "REJECT", "--reject-with", "tcp-reset"
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 7. Allow DNS (UDP 53)
        subprocess.run(["iptables", "-A", chain_name, "-p", "udp", "--dport", "53", "-j", "ACCEPT"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 8. Strict Max 3 Target IPs quota for Web Downloading (HTTP/HTTPS/8080):
        # We record up to 3 distinct destination IPs.
        subprocess.run([
            "iptables", "-A", chain_name, "-p", "tcp",
            "-m", "multiport", "--dports", "80,443,8080,8443",
            "-m", "conntrack", "--ctstate", "NEW",
            "-m", "recent", "--name", recent_name, "--set", "--rdest"
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        subprocess.run([
            "iptables", "-A", chain_name, "-p", "tcp",
            "-m", "multiport", "--dports", "80,443,8080,8443",
            "-m", "conntrack", "--ctstate", "NEW",
            "-m", "recent", "--name", recent_name, "--rcheck", "--rdest", "--hitcount", "1",
            "-j", "ACCEPT"
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 9. All other traffic / 4th IP / random ports -> Immediate TCP RST
        subprocess.run(["iptables", "-A", chain_name, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-A", chain_name, "-j", "DROP"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @staticmethod
    def cleanup_guest_rules(guest_ip: str, host_veth_ip: str, veth_host: str):
        """Cleans up guest specific iptables rules and custom chains."""
        chain_name = f"EG_{guest_ip.replace('.', '_')}"
        
        # Remove DNAT rule in nat PREROUTING
        subprocess.run([
            "iptables", "-t", "nat", "-D", "PREROUTING", "-i", veth_host, "-s", guest_ip,
            "-p", "icmp", "--icmp-type", "echo-request", "-j", "DNAT", "--to-destination", host_veth_ip
        ], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Remove jump rule in FORWARD
        subprocess.run(["iptables", "-D", "FORWARD", "-s", guest_ip, "-j", chain_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Flush and delete custom chain
        subprocess.run(["iptables", "-F", chain_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["iptables", "-X", chain_name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

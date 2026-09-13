import asyncio
import socket
import struct
import logging
from typing import Optional, Callable
from ghostpot.database import Database

logger = logging.getLogger("ghostpot.dns_dpi")

# DNS Record Types mapping
DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    255: "ANY"
}


def parse_dns_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decodes DNS query name domain components."""
    labels = []
    jumped = False
    original_offset = offset
    length = len(data)

    while offset < length:
        length_byte = data[offset]
        if length_byte == 0:
            offset += 1
            break
        # Pointer compression (0xC0)
        if (length_byte & 0xC0) == 0xC0:
            if offset + 1 >= length:
                break
            pointer = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            offset += 2
            if not jumped:
                original_offset = offset
                jumped = True
            offset = pointer
            continue
        
        offset += 1
        if offset + length_byte > length:
            break
        label = data[offset:offset+length_byte].decode("utf-8", "ignore")
        labels.append(label)
        offset += length_byte

    domain = ".".join(labels)
    return domain, original_offset if jumped else offset


def parse_dns_packet(data: bytes) -> Optional[dict]:
    """Parses raw DNS packet for Deep Packet Inspection (DPI)."""
    if len(data) < 12:
        return None

    try:
        tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", data[:12])
        is_response = bool(flags & 0x8000)
        
        offset = 12
        queries = []
        for _ in range(qd_count):
            qname, offset = parse_dns_name(data, offset)
            if offset + 4 <= len(data):
                qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
                offset += 4
                queries.append({
                    "name": qname,
                    "type": DNS_TYPES.get(qtype, f"TYPE_{qtype}"),
                    "class": qclass
                })

        return {
            "tx_id": tx_id,
            "is_response": is_response,
            "queries": queries,
            "raw_len": len(data)
        }
    except Exception as e:
        logger.debug(f"DNS DPI parse error: {e}")
        return None


class DNSDPIProxyProtocol(asyncio.DatagramProtocol):
    def __init__(self, db: Database, upstream_dns: str = "1.1.1.1", on_query: Optional[Callable] = None):
        self.db = db
        self.upstream_dns = upstream_dns
        self.on_query = on_query
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        client_ip, client_port = addr
        parsed = parse_dns_packet(data)
        
        if parsed and parsed.get("queries"):
            for q in parsed["queries"]:
                qname = q["name"]
                qtype = q["type"]
                logger.info(f"[🔍 DNS-DPI] Request from {client_ip}:{client_port} → Domain: {qname} (Type: {qtype})")
                
                # Record to Database as security event
                asyncio.create_task(self.db.record_event({
                    "eventid": "ghostpot.dns.query",
                    "src_ip": client_ip,
                    "session": f"dns_{client_ip.replace('.', '_')}",
                    "domain": qname,
                    "qtype": qtype,
                    "message": f"DNS Query: {qname} [{qtype}]"
                }))
                
                if self.on_query:
                    self.on_query(client_ip, qname, qtype)

        # Forward DNS request to real upstream DNS server and relay response back to guest
        asyncio.create_task(self._forward_upstream(data, addr))

    async def _forward_upstream(self, data: bytes, client_addr):
        try:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            await loop.sock_connect(sock, (self.upstream_dns, 53))
            await loop.sock_sendall(sock, data)
            resp = await loop.sock_recv(sock, 4096)
            sock.close()
            if self.transport and not self.transport.is_closing():
                self.transport.sendto(resp, client_addr)
        except Exception as e:
            logger.warning(f"DNS upstream relay error ({self.upstream_dns}): {e}")


class TransparentRawDNSSniffer:
    """
    Transparent Raw Network DPI Sniffer:
    Sniffs all outgoing UDP/53 (DNS) packets directly off the host network interfaces (veth).
    Zero guest footprint: Guest sees standard default 1.1.1.1 / 8.8.8.8 in /etc/resolv.conf.
    """
    def __init__(self, db: Database, on_query: Optional[Callable] = None):
        self.db = db
        self.on_query = on_query
        self._running = False
        self._task = None

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._sniff_loop())
        logger.info("[+] Transparent Kernel-Level DNS DPI Sniffer ACTIVE (Zero-Guest-Deception mode)")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("[-] Transparent DNS DPI Sniffer stopped.")

    async def _sniff_loop(self):
        loop = asyncio.get_running_loop()
        try:
            # Create Raw Ethernet / IP Socket to capture all egress DNS
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            raw_sock.setblocking(False)
        except Exception as e:
            logger.warning(f"Raw Socket creation warning (falling back to standard DPI): {e}")
            return

        while self._running:
            try:
                packet = await loop.sock_recv(raw_sock, 65535)
                if len(packet) < 28:
                    continue

                # Parse IPv4 Header (Minimum 20 bytes)
                ip_header_len = (packet[0] & 0x0F) * 4
                src_ip = socket.inet_ntoa(packet[12:16])
                dst_ip = socket.inet_ntoa(packet[16:20])

                # Parse UDP Header (8 bytes)
                udp_header = packet[ip_header_len:ip_header_len+8]
                if len(udp_header) < 8:
                    continue
                src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", udp_header)

                # Filter DNS Destination port 53
                if dst_port == 53:
                    dns_payload = packet[ip_header_len+8:]
                    parsed = parse_dns_packet(dns_payload)
                    if parsed and parsed.get("queries"):
                        for q in parsed["queries"]:
                            qname = q["name"]
                            qtype = q["type"]
                            logger.info(f"[🔍 TRANSPARENT DNS-DPI] Guest {src_ip}:{src_port} → {dst_ip}:53 | Query: {qname} [{qtype}]")
                            
                            asyncio.create_task(self.db.record_event({
                                "eventid": "ghostpot.dns.query",
                                "src_ip": src_ip,
                                "session": f"dns_{src_ip.replace('.', '_')}",
                                "domain": qname,
                                "qtype": qtype,
                                "resolver": dst_ip,
                                "message": f"DNS Query to {dst_ip}: {qname} [{qtype}]"
                            }))
                            
                            if self.on_query:
                                self.on_query(src_ip, qname, qtype)
            except asyncio.CancelledError:
                break
            except Exception as e:
                await asyncio.sleep(0.05)


class DNSDPIServer:
    def __init__(self, db: Database, listen_host: str = "0.0.0.0", listen_port: int = 53, upstream_dns: str = "1.1.1.1"):
        self.db = db
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.upstream_dns = upstream_dns
        self.transport = None
        self.raw_sniffer = TransparentRawDNSSniffer(db)

    async def start(self):
        # 1. Start Transparent Kernel Raw Socket Sniffer
        await self.raw_sniffer.start()

        # 2. Start UDP:53 Resolver
        try:
            loop = asyncio.get_running_loop()
            self.transport, _ = await loop.create_datagram_endpoint(
                lambda: DNSDPIProxyProtocol(self.db, self.upstream_dns),
                local_addr=(self.listen_host, self.listen_port)
            )
            logger.info(f"[+] DNS DPI Gateway active on {self.listen_host}:{self.listen_port} (Upstream: {self.upstream_dns})")
        except Exception as e:
            logger.debug(f"DNS DPI standard binding note: {e}")

    async def stop(self):
        await self.raw_sniffer.stop()
        if self.transport:
            self.transport.close()
            logger.info("[-] DNS DPI Server stopped.")

#!/usr/bin/env python3
import asyncio
import signal
import sys
import logging
import uvicorn
from ghostpot.config import load_config
from ghostpot.database import Database
from ghostpot.vm_manager import VMPoolManager
from ghostpot.l4_proxy import L4ProxyServer
from ghostpot.web_server import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("ghostpot")

BANNER = """\033[1;36m
   ______ __                 __                __ 
  / ____// /_   ____   _____/ /_ ____   ____  / /_
 / / __ / __ \ / __ \ / ___/ __// __ \ / __ \/ __/
/ /_/ // / / // /_/ /(__  )/ /_ / /_/ // /_/ / /_  
\____//_/ /_/ \____//____/ \__// .___/ \____/ \__/ 
                              /_/                 
\033[0m\033[1;30m[ Stealth MicroVM High-Interaction Honeypot v1.0 ]\033[0m
"""

async def main():
    config = load_config("config.yaml")
    
    # 1. Print Banner & Configuration
    print(BANNER)
    kvm_status = "\033[1;32mHardware KVM (Superfast)\033[0m" if config.is_kvm_available() else "\033[1;33mSoftware TCG (No /dev/kvm)\033[0m"
    ssh_status = f"\033[1;32mACTIVE (0.0.0.0:{config.services.ssh.listen_port})\033[0m" if config.services.ssh.enabled else "\033[1;31mDISABLED\033[0m"
    telnet_status = f"\033[1;32mACTIVE (0.0.0.0:{config.services.telnet.listen_port})\033[0m" if config.services.telnet.enabled else "\033[1;31mDISABLED\033[0m"
    
    secret_url = f"http://YOUR_SERVER_IP:{config.web.port}/{config.web.secret_slug}/"
    
    print(f"[*] Hypervisor Mode:    {kvm_status}")
    print(f"[*] SSH Honeypot:       {ssh_status}")
    print(f"[*] Telnet Honeypot:    {telnet_status}")
    print(f"[*] Web Server Port:    \033[1;37m{config.web.port}\033[0m (Crawler-Immune)")
    print(f"[*] Secret Web Panel:   \033[1;35m{secret_url}\033[0m")
    print("-" * 65)

    # 2. Initialize Database
    db = Database(config.storage.db_path)
    await db.connect()

    # 3. Start Intelligent Auth Manager (IP Binding & Bruteforce Simulator)
    from ghostpot.auth_manager import AuthManager
    auth_mgr = AuthManager(config, db)
    await auth_mgr.start()

    # 4. Initialize MicroVM Pool Manager
    vm_pool = VMPoolManager(config)
    await vm_pool.start()

    # 5. Start L4 Honeypot Proxy (for Telnet)
    proxy_l4 = L4ProxyServer(config, db, vm_pool, auth_mgr)
    await proxy_l4.start()

    # 5.5 Start L7 MitM Honeypot Proxy (for SSH Polymorphism)
    from ghostpot.l7_mitm import L7MitmProxyServer
    proxy_l7 = L7MitmProxyServer(config, db, vm_pool)
    await proxy_l7.start()

    # 5.6 Start DNS DPI Sniffer & Resolver
    from ghostpot.dns_dpi import DNSDPIServer
    dns_dpi = DNSDPIServer(db, listen_host="0.0.0.0", listen_port=53, upstream_dns="1.1.1.1")
    await dns_dpi.start()

    # 6. Start Web Server Application
    app = create_app(config, db)
    uv_config = uvicorn.Config(
        app,
        host=config.web.host,
        port=config.web.port,
        log_level="warning",
        access_log=False
    )
    server = uvicorn.Server(uv_config)

    # 6. Graceful Shutdown Setup
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _signal_handler():
        logger.info("[!] Stopping Ghostpot services...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _signal_handler)

    # Run web server and wait for stop event
    server_task = asyncio.create_task(server.serve())
    await stop_event.wait()

    # Teardown
    logger.info("[*] Shutting down L4/L7 proxies, DNS DPI, MicroVMs, and database...")
    await proxy_l4.stop()
    await proxy_l7.stop()
    await dns_dpi.stop()
    await vm_pool.shutdown()
    await auth_mgr.stop()
    from ghostpot.egress_guard import EgressGuard
    EgressGuard.cleanup_global_rules()
    server.should_exit = True
    await server_task
    await db.close()
    logger.info("[✓] Ghostpot stopped cleanly.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass

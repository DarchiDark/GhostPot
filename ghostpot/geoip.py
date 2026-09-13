import urllib.request
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("ghostpot.geoip")

_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

def lookup_ip(ip: str) -> Dict[str, Any]:
    if not ip or ip in ("127.0.0.1", "localhost", "unknown") or ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        return {"country": "LAN", "countryCode": "LAN", "lat": 0.0, "lng": 0.0, "city": "Local Network"}

    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]

    # Try fast online lookup with short timeout
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,lat,lon,city"
        req = urllib.request.Request(url, headers={"User-Agent": "Ghostpot/1.0"})
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                res = {
                    "country": data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "UN"),
                    "lat": float(data.get("lat", 0.0)),
                    "lng": float(data.get("lon", 0.0)),
                    "city": data.get("city", "")
                }
                _GEO_CACHE[ip] = res
                return res
    except Exception as e:
        logger.debug(f"GeoIP lookup failed for {ip}: {e}")

    default_res = {"country": "Unknown", "countryCode": "UN", "lat": 0.0, "lng": 0.0, "city": ""}
    _GEO_CACHE[ip] = default_res
    return default_res

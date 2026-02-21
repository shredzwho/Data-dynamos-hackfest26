import os
import geoip2.database
from functools import lru_cache
import logging

logger = logging.getLogger(__name__)

# Path to the free GeoLite2 Country database we just downloaded
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "GeoLite2-Country.mmdb")

class GeoIPService:
    """
    Looks up the geographical origin of an IPv4 address.
    Uses an in-memory LRU cache to prevent disk I/O bottlenecks during high-speed packet sniffing.
    """
    _reader = None

    @classmethod
    def get_reader(cls):
        if cls._reader is None:
            try:
                if os.path.exists(DB_PATH):
                    cls._reader = geoip2.database.Reader(DB_PATH)
                    logger.info("GeoIPService: MaxMind Database loaded successfully.")
                else:
                    logger.warning(f"GeoIPService: Database not found at {DB_PATH}")
            except Exception as e:
                logger.error(f"GeoIPService: Failed to load database: {e}")
        return cls._reader

    @classmethod
    @lru_cache(maxsize=10000)
    def lookup_ip(cls, ip_address: str) -> dict:
        """
        Returns a dictionary containing the ISO Country Code and Full Name.
        Example: {'code': 'US', 'name': 'United States'}
        """
        # Exclude loopback and private subnets
        if ip_address.startswith("127.") or ip_address.startswith("192.168.") or ip_address.startswith("10."):
            return {"code": "LOCAL", "name": "Local Network"}

        reader = cls.get_reader()
        if not reader:
            return {"code": "UNKNOWN", "name": "Unknown Entity"}

        try:
            response = reader.country(ip_address)
            return {
                "code": response.country.iso_code or "UNKNOWN",
                "name": response.country.name or "Unknown Entity"
            }
        except geoip2.errors.AddressNotFoundError:
            return {"code": "UNKNOWN", "name": "Unknown Entity"}
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return {"code": "ERROR", "name": "Error"}

    @classmethod
    def get_geo_risk_factor(cls, country_code: str) -> float:
        """
        Phase 18 ML Feature extraction: Quantifies risk based on geographic origin.
        """
        # Example high-risk origins (Replace with actual SOC intel)
        HIGH_RISK = ["RU", "KP", "CN", "IR"]
        MEDIUM_RISK = ["BR", "IN", "TR", "VN"]
        
        if country_code in HIGH_RISK:
            return 1.0 # 100% Risk multiplier
        elif country_code in MEDIUM_RISK:
            return 0.5 # 50% Risk multiplier
        elif country_code == "LOCAL":
            return 0.0 # Trusted Local Subnet
        else:
            return 0.1 # Baseline ambient internet noise

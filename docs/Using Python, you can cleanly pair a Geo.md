# Using Python for GeoIP and Flag Icons

Using Python, you can cleanly pair a GeoIP lookup engine (like MaxMind GeoIP2 or the local db-ip database) with a flag icon library. Because you are on a Linux environment, you can manage this efficiently using local SVGs or dynamic CDN URLs.
Here is the complete implementation using the lipis/flag-icons naming convention (lowercase_iso_code.svg).

## Project Setup

Install the official MaxMind GeoIP package to parse your .mmdb database file:
bash
pip install geoip2
Use code with caution.
(If you need a free local database file, you can download the GeoLite2-Country.mmdb from MaxMind or DB-IP).

### Python Implementation

```python

import os
import geoip2.database

class GeoIPFlagResolver:
    def __init__(self, db_path: str):
        """
        Initializes the GeoIP database reader.
        """
        if not os.path.exists(db_path):
            raise FileNotFoundError(f"GeoIP Database not found at: {db_path}")
        self.reader = geoip2.database.Reader(db_path)

    def get_flag_details(self, ip_address: str) -> dict:
        """
        Looks up an IP address and returns the country name,
        ISO code, local file path template, and CDN URL template.
        """
        try:
            response = self.reader.country(ip_address)
            # GeoIP returns uppercase codes (e.g., 'US', 'VN')
            iso_code_upper = response.country.iso_code

            if not iso_code_upper:
                return self._fallback_response()

            iso_code_lower = iso_code_upper.lower()

            return {
                "success": True,
                "ip": ip_address,
                "country_name": response.country.name,
                "iso_code": iso_code_upper,
                # URL mapping for frontend/web clients
                "cdn_url_4x3": f"https://jsdelivr.net{iso_code_lower}.svg",
                "cdn_url_1x1": f"https://jsdelivr.net{iso_code_lower}.svg",
                # File system path mapping for local asset compiling/rendering
                "local_svg_path": f"/usr/share/flags/4x3/{iso_code_lower}.svg"
            }

        except geoip2.errors.AddressNotFoundError:
            return self._fallback_response(reason="IP address not found in database.")
        except Exception as e:
            return self._fallback_response(reason=str(e))

    def _fallback_response(self, reason: str = "Unknown/Internal IP") -> dict:
        return {
            "success": False,
            "reason": reason,
            "country_name": "Unknown",
            "iso_code": "XX",
            "cdn_url_4x3": "https://jsdelivr.netxx.svg",
            "local_svg_path": None
        }

    def close(self):
        self.reader.close()
```

### Example Usage

```python

if __name__ == "__main__":
    # Replace with the actual path to your downloaded .mmdb file
    DB_FILE = "GeoLite2-Country.mmdb"

    # Initialize resolver
    try:
        resolver = GeoIPFlagResolver(DB_FILE)

        # Test with a known public IP address
        test_ip = "8.8.8.8"
        flag_info = resolver.get_flag_details(test_ip)

        print(f"IP: {flag_info['ip']}")
        print(f"Country: {flag_info['country_name']} ({flag_info['iso_code']})")
        print(f"SVG CDN URL: {flag_info['cdn_url_4x3']}")

        resolver.close()
    except FileNotFoundError as e:
        print(f"Setup Error: {e}")
```

Use code with caution.

### Quick Linux Deployment Tips

- Local Assets Alternative: If you want to keep the SVGs entirely offline on your Linux system instead of hitting a CDN, you can clone the repository directly into your project or assets asset path:

```bash
git clone --depth 1 <https://github.com> static/flag-icons
```

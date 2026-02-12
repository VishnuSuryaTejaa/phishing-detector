import requests

def get_geolocation(ip: str):
    try:
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )
        data = response.json()

        return {
            "country": data.get("country"),
            "isp": data.get("isp")
        }

    except Exception:
        return {
            "country": None,
            "isp": None
        }

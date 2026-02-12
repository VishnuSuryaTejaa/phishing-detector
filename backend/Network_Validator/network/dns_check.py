import socket

def dns_lookup(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        return {
            "dns_resolves": True,
            "ip_address": ip
        }
    except Exception:
        return {
            "dns_resolves": False,
            "ip_address": None
        }

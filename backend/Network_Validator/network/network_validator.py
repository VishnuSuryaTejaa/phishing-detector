from .dns_check import dns_lookup
from .whois_check import get_domain_age
from .ssl_check import check_ssl
from .geo_check import get_geolocation


HIGH_RISK_COUNTRIES = [
    "Unknown",
    "Russia",
    "North Korea",
    "Iran",
    "Netherlands"
]



def calculate_network_risk(dns, age_days, ssl_valid, country):
    score = 0
    reasons = []

    # DNS Check
    if not dns:
        score += 4
        reasons.append("Domain does not resolve")

    # Domain Age Check
    if age_days is None:
        score += 2
        reasons.append("Domain age could not be determined (WHOIS hidden)")

    elif age_days < 7:
        score += 6
        reasons.append("Domain is extremely new (<7 days)")

    elif age_days < 30:
        score += 4
        reasons.append("Domain is newly registered (<30 days)")

    elif age_days < 90:
       score += 2
       reasons.append("Domain is relatively new (<90 days)")

    # SSL Check
    if not ssl_valid:
        score += 3
        reasons.append("Invalid or missing SSL certificate")

    # Hosting Country Check
    if country in HIGH_RISK_COUNTRIES:
        score += 2
        reasons.append("Hosted in high-risk region")
    elif country is None:
        score += 1
        reasons.append("Hosting country unknown")

    return min(score, 15), reasons



def network_scan(domain: str):

    dns_result = dns_lookup(domain)
    age_days = get_domain_age(domain)
    ssl_valid = check_ssl(domain)

    country = None
    isp = None

    if dns_result["dns_resolves"]:
        geo = get_geolocation(dns_result["ip_address"])
        country = geo["country"]
        isp = geo["isp"]

    score, reasons = calculate_network_risk(
        dns_result["dns_resolves"],
        age_days,
        ssl_valid,
        country
    )

    return {
        "dns_resolves": dns_result["dns_resolves"],
        "ip_address": dns_result["ip_address"],
        "domain_age_days": age_days,
        "ssl_valid": ssl_valid,
        "hosting_country": country,
        "isp": isp,
        "network_risk_score": score,
        "reasons": reasons
    }

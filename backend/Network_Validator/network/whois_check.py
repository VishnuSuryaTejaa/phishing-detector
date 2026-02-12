import whois
from datetime import datetime

def get_domain_age(domain: str):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return None

        if isinstance(creation_date, str):
            creation_date = datetime.strptime(
                creation_date[:10], "%Y-%m-%d"
            )

        return (datetime.now() - creation_date).days

    except Exception:
        return None

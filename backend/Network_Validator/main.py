from network.network_validator import network_scan

if __name__ == "__main__":
    
    domain = input("Enter domain to scan: ")
    
    result = network_scan(domain)

    print("\n===== NETWORK SCAN RESULT =====\n")
    
    for key, value in result.items():
        print(f"{key}: {value}")

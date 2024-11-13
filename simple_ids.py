# simple_ids.py

# Set the threshold for failed login attempts
FAILED_ATTEMPT_THRESHOLD = 1  # Lowering the threshold to 1

def read_log_file(filename):
    """Reads the log file and returns lines as a list."""
    with open(filename, 'r') as file:
        return file.readlines()

def detect_intrusions(log_lines):
    """Detects IP addresses with repeated failed login attempts."""
    failed_attempts = {}
    suspicious_ips = []

    for line in log_lines:
        # Debug: Print each line to see if it's being read correctly
        print(f"Processing line: {line.strip()}")
        
        # Check if the line contains a failed login attempt
        if "Action: LOGIN, Status: FAILED" in line:
            # Extract the IP address from the line
            ip_start = line.find("IP: ") + 4
            ip_end = line.find(",", ip_start)
            ip_address = line[ip_start:ip_end]
            
            # Debug: Print the extracted IP address
            print(f"Extracted IP address: {ip_address}")
            
            # Increment the failed attempt count for this IP
            if ip_address in failed_attempts:
                failed_attempts[ip_address] += 1
            else:
                failed_attempts[ip_address] = 1
            
            # Check if the failed attempt count exceeds the threshold
            if failed_attempts[ip_address] > FAILED_ATTEMPT_THRESHOLD:
                suspicious_ips.append(ip_address)

    return suspicious_ips

def main():
    # Read the log file
    log_lines = read_log_file("network_log.txt")
    
    # Detect suspicious IP addresses
    suspicious_ips = detect_intrusions(log_lines)

    # Print the results
    if suspicious_ips:
        print("Suspicious IP addresses detected:")
        for ip in suspicious_ips:
            print(f"- {ip}")
    else:
        print("No suspicious activity detected.")

if __name__ == "__main__":
    main()

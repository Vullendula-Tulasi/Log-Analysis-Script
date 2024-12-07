import re
import csv

# Open and read the sample.log file
with open("sample.log", "r") as file:
    logs = file.readlines()

# Initialize data structures for analysis
requests_per_ip = {}
failed_logins = {}
endpoints = {}

# Analyze each line in the log file
for line in logs:
    # Extract IP address
    ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
    if ip_match:
        ip_address = ip_match.group(1)
        requests_per_ip[ip_address] = requests_per_ip.get(ip_address, 0) + 1

    # Check for failed logins
    if "Failed login" in line:
        if ip_address:  # Ensure IP address exists
            failed_logins[ip_address] = failed_logins.get(ip_address, 0) + 1

    # Extract endpoint
    endpoint_match = re.search(r"\"[A-Z]+\s+([^\s]+)", line)
    if endpoint_match:
        endpoint = endpoint_match.group(1)
        endpoints[endpoint] = endpoints.get(endpoint, 0) + 1

# Find the most accessed endpoint
most_accessed_endpoint = max(endpoints.items(), key=lambda x: x[1])

# Terminal Output
print("Requests per IP Address:")
for ip, count in requests_per_ip.items():
    print(f"{ip:<20} {count}")
print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
print("\nSuspicious Activity Detected:")
if failed_logins:
    print(f"{'IP Address':<20} {'Failed Login Attempts'}")
    for ip, count in failed_logins.items():
        print(f"{ip:<20} {count}")
else:
    print("No suspicious activity detected.")

# Save Results to a CSV File
with open("log_analysis_results.csv", "w", newline="") as csvfile:
    writer = csv.writer(csvfile)

    # Section 1: Requests per IP Address
    writer.writerow(["Requests per IP Address"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(requests_per_ip.items())
    writer.writerow([])  # Blank row

    # Section 2: Most Frequently Accessed Endpoint
    writer.writerow(["Most Frequently Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
    writer.writerow([])  # Blank row

    # Section 3: Suspicious Activity
    writer.writerow(["Suspicious Activity Detected"])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(failed_logins.items())

print("\nLog analysis results have been saved to 'log_analysis_results.csv'.")

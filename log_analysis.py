import re
import csv
from collections import defaultdict

# Configuration
LOG_FILE = "sample.log"
CSV_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Parse the log file and extract relevant data.
    """
    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(file_path, "r") as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(r"^(\d+\.\d+\.\d+\.\d+)", line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1

            # Extract endpoint and status code
            endpoint_match = re.search(r'"[A-Z]+ (\/[^\s]*)', line)
            status_code_match = re.search(r'" (\d{3}) ', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_access[endpoint] += 1

            # Detect failed login attempts
            if status_code_match and status_code_match.group(1) == "401":
                failed_login_attempts[ip] += 1

    return ip_requests, endpoint_access, failed_login_attempts

def count_requests_per_ip(ip_requests):
    """
    Sort and return IP requests in descending order.
    """
    return sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)

def most_frequently_accessed_endpoint(endpoint_access):
    """
    Identify the most frequently accessed endpoint.
    """
    return max(endpoint_access.items(), key=lambda x: x[1])

def detect_suspicious_activity(failed_login_attempts, threshold):
    """
    Detect suspicious activity based on failed login attempts.
    """
    return {ip: count for ip, count in failed_login_attempts.items() if count > threshold}

def save_to_csv(ip_requests, most_accessed, suspicious_activity):
    """
    Save analysis results to a CSV file.
    """
    with open(CSV_FILE, mode="w", newline="") as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoint_access, failed_login_attempts = parse_log_file(LOG_FILE)

    # Analyze data
    ip_requests_sorted = count_requests_per_ip(ip_requests)
    most_accessed = most_frequently_accessed_endpoint(endpoint_access)
    suspicious_activity = detect_suspicious_activity(failed_login_attempts, FAILED_LOGIN_THRESHOLD)

    # Display results
    print("Requests per IP:")
    for ip, count in ip_requests_sorted:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_activity.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    save_to_csv(ip_requests_sorted, most_accessed, suspicious_activity)
    print(f"\nResults saved to {CSV_FILE}")

if __name__ == "__main__":
    main()

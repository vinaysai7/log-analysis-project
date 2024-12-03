import re
from collections import Counter
import csv

FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """
    Parses the log file to extract IP addresses, endpoints, and failed login attempts.

    Args:
        file_path (str): Path to the log file.

    Returns:
        tuple: Counters for IP requests, endpoints, and failed login attempts by IP.
    """
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    endpoint_pattern = re.compile(r'\"[A-Z]+\s(/[^ ]*)\s')
    failed_login_pattern = re.compile(r'401|Invalid credentials')

    ip_counts = Counter()
    endpoint_counts = Counter()
    failed_login_counts = Counter()

    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:

                ip_matches = ip_pattern.findall(line)
                if ip_matches:
                    ip_counts.update(ip_matches)

                
                endpoint_match = endpoint_pattern.search(line)
                if endpoint_match:
                    endpoint_counts.update([endpoint_match.group(1)])

                
                if failed_login_pattern.search(line):
                    for ip in ip_matches:
                        failed_login_counts.update([ip])
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return {}, {}, {}

    return ip_counts, endpoint_counts, failed_login_counts

def display_suspicious_activity(failed_login_counts, threshold):

    suspicious_ips = {ip: count for ip, count in failed_login_counts.items() if count > threshold}
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print(f"{'IP Address':<20}{'Failed Login Attempts':<20}")
        print("-" * 40)
        for ip, count in sorted(suspicious_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:<20}{count:<20}")
    else:
        print("No suspicious activity detected.")

def save_results_to_csv(ip_counts, endpoint_counts, failed_login_counts, output_file):
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])

        writer.writerow([])
        writer.writerow(['Endpoint', 'Access Count'])
        for endpoint, count in endpoint_counts.most_common():
            writer.writerow([endpoint, count])

        writer.writerow([])
        writer.writerow(['IP Address', 'Failed Login Attempts'])
        for ip, count in failed_login_counts.most_common():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

    print(f"Results saved to {output_file}")

def main():
    log_file_path = input("Enter the path to the log file: ").strip().strip('"')
    ip_counts, endpoint_counts, failed_login_counts = parse_log_file(log_file_path)

    if ip_counts or endpoint_counts or failed_login_counts:
        print("\nGeneral Analysis Results:")
        print(f"{'IP Address':<20}{'Request Count':<15}")
        print("-" * 35)
        for ip, count in ip_counts.most_common():
            print(f"{ip:<20}{count:<15}")

        print("\nMost Frequently Accessed Endpoint:")
        if endpoint_counts:
            most_common_endpoint, access_count = endpoint_counts.most_common(1)[0]
            print(f"{most_common_endpoint} (Accessed {access_count} times)")
        else:
            print("No endpoints found.")


        display_suspicious_activity(failed_login_counts, FAILED_LOGIN_THRESHOLD)


        save_results_to_csv(ip_counts, endpoint_counts, failed_login_counts, "log_analysis_results.csv")

if __name__ == "__main__":
    main()

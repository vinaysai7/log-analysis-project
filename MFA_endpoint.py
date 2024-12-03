import re
from collections import Counter
import csv

def parse_log_file(file_path):
    
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    endpoint_pattern = re.compile(r'\"[A-Z]+\s(/[^ ]*)\s') 
    ip_counts = Counter()
    endpoint_counts = Counter()

    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                
                ip_matches = ip_pattern.findall(line)
                if ip_matches:
                    ip_counts.update(ip_matches)
                
                
                endpoint_match = endpoint_pattern.search(line)
                if endpoint_match:
                    endpoint_counts.update([endpoint_match.group(1)])
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return {}, {}

    return ip_counts, endpoint_counts

def save_results_to_csv(ip_counts, endpoint_counts, output_file):
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Request Count']) 
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])

        writer.writerow([]) 
        writer.writerow(['Endpoint', 'Access Count']) 
        for endpoint, count in endpoint_counts.most_common():
            writer.writerow([endpoint, count])

    print(f"Results saved to {output_file}")

def display_results(ip_counts, endpoint_counts):
    
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

def main():
    log_file_path = input("Enter the path to the log file: ").strip().strip('"')
    ip_counts, endpoint_counts = parse_log_file(log_file_path)
    if ip_counts or endpoint_counts:
        display_results(ip_counts, endpoint_counts)
        save_results_to_csv(ip_counts, endpoint_counts, "log_analysis_results.csv")

if __name__ == "__main__":
    main()

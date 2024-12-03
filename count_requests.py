import re
from collections import Counter
import csv

def parse_log_file(file_path):
    
    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    ip_counts = Counter()

    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                
                ip_matches = ip_pattern.findall(line)
                if ip_matches:
                    ip_counts.update(ip_matches)
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return {}

    return ip_counts

def save_results_to_csv(ip_counts, output_file):
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['IP Address', 'Request Count']) 
        for ip, count in ip_counts.most_common():
            writer.writerow([ip, count])
    print(f"Results saved to {output_file}")

def display_results(ip_counts):
    
    print(f"{'IP Address':<20}{'Request Count':<15}")
    print("-" * 35)
    for ip, count in ip_counts.most_common():
        print(f"{ip:<20}{count:<15}")

def main():
    log_file_path = input("Enter the path to the log file: ").strip().strip('"')
    ip_counts = parse_log_file(log_file_path)
    if ip_counts:
        display_results(ip_counts)
        save_results_to_csv(ip_counts, "log_analysis_results.csv")

if __name__ == "__main__":
    main()


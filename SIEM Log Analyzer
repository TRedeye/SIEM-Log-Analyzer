import re
import argparse

def analyze_log(file_path):
    suspicious_ips = {}
    sensitive_areas = ['/admin', '/login', '/wp-admin', '/phpmyadmin', '/config']
    
    try:
        with open(file_path, 'r') as log:
            lines = log.readlines()
    except FileNotFoundError:
        print(f"[!] Log file not found: {file_path}")
        return

    # Parse each log line
    for line in lines:
        match = re.search(r'(\d+\.\d+\.\d+\.\d+).+"GET (.+?) HTTP.+?" (\d+)', line)
        if match:
            ip, url, status = match.groups()

            if ip not in suspicious_ips:
                suspicious_ips[ip] = {'404': 0, 'sensitive': 0}

            if status == '404':
                suspicious_ips[ip]['404'] += 1

            if any(area in url for area in sensitive_areas):
                suspicious_ips[ip]['sensitive'] += 1

    # Display alerts
    print("\n[!] Suspicious Activity Detected:\n")
    for ip, actions in suspicious_ips.items():
        if actions['404'] >= 5:
            print(f"[404 ALERT] IP: {ip} — {actions['404']} times 404 errors")
        if actions['sensitive'] > 0:
            print(f"[Sensitive Access ALERT] IP: {ip} — {actions['sensitive']} attempts to sensitive areas")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Log Analyzer for Suspicious Activity")
    parser.add_argument('--logfile', type=str, required=True, help='Path to Apache access.log file')
    args = parser.parse_args()

    analyze_log(args.logfile)

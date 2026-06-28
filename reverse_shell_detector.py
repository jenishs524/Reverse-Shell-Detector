#!/usr/bin/env python3
import psutil
import time
import sys
from datetime import datetime

# Common reverse shell ports
SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337, 8080, 443, 80]

# Process names often associated with shells
SUSPICIOUS_PROCESSES = ['nc', 'netcat', 'ncat', 'socat', 'bash', 'sh', 'python', 'perl', 'ruby', 'php', 'telnet']

def check_connections():
    """Scan all network connections and flag suspicious ones."""
    alerts = []
    for conn in psutil.net_connections(kind='inet'):
        # Only consider established connections (or listen, but we want outbound)
        if conn.status not in ('ESTABLISHED', 'SYN_SENT', 'CLOSE_WAIT'):
            continue
        if not conn.raddr:
            continue  # no remote address
        local_ip, local_port = conn.laddr
        remote_ip, remote_port = conn.raddr
        pid = conn.pid
        if pid is None:
            continue
        try:
            proc = psutil.Process(pid)
            proc_name = proc.name()
            proc_user = proc.username()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        # Check for suspicious remote port
        if remote_port in SUSPICIOUS_PORTS:
            alerts.append({
                'pid': pid,
                'process': proc_name,
                'user': proc_user,
                'local': f"{local_ip}:{local_port}",
                'remote': f"{remote_ip}:{remote_port}",
                'reason': f"Remote port {remote_port} is commonly used for reverse shells"
            })
        # Check for suspicious process name
        elif any(s in proc_name.lower() for s in SUSPICIOUS_PROCESSES):
            alerts.append({
                'pid': pid,
                'process': proc_name,
                'user': proc_user,
                'local': f"{local_ip}:{local_port}",
                'remote': f"{remote_ip}:{remote_port}",
                'reason': f"Suspicious process name: {proc_name}"
            })
    return alerts

def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--once':
        # One-shot scan
        alerts = check_connections()
        if alerts:
            print("\n[!] Potential reverse shells detected:")
            for a in alerts:
                print(f"  PID {a['pid']} ({a['process']}, user: {a['user']})")
                print(f"    {a['local']} -> {a['remote']}")
                print(f"    Reason: {a['reason']}")
        else:
            print("[+] No suspicious connections found.")
        return

    # Continuous monitoring
    print("=" * 60)
    print("  REVERSE SHELL DETECTOR (continuous mode)")
    print("=" * 60)
    print("[*] Press Ctrl+C to stop")
    print("[*] Monitoring for suspicious outbound connections...")
    try:
        while True:
            alerts = check_connections()
            if alerts:
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] [!] ALERT: {len(alerts)} suspicious connection(s)")
                for a in alerts:
                    print(f"  PID {a['pid']} ({a['process']}, user: {a['user']})")
                    print(f"    {a['local']} -> {a['remote']}")
                    print(f"    Reason: {a['reason']}")
            else:
                # Print a dot every 10 seconds to show it's alive
                print(".", end="", flush=True)
            time.sleep(5)
    except KeyboardInterrupt:
        print("\n[*] Stopped.")

if __name__ == "__main__":
    main()

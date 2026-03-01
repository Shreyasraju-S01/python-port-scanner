import socket
import time
from datetime import datetime

# Common services
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    3306: "MySQL",
    5900: "VNC",
    8080: "HTTP-Alt"
}

# Known vulnerabilities
vulnerability_info = {
    21: "FTP may allow anonymous login.",
    23: "Telnet is insecure (unencrypted communication).",
    25: "SMTP may allow email spoofing.",
    139: "NetBIOS may expose file sharing.",
    445: "SMB may be vulnerable to ransomware attacks.",
    3389: "RDP may be targeted by brute-force attacks."
}

def scan_ports(target, start_port, end_port):
    open_ports = []

    print(f"\nScanning target: {target}")
    print(f"Scanning ports {start_port}–{end_port}...\n")

    total_ports = end_port - start_port + 1
    current = 0

    start_time = time.time()

    for port in range(start_port, end_port + 1):
        current += 1
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)


        result = sock.connect_ex((target, port))

        # Progress display
        print(f"\rScanning port {port}/{end_port}...", end="")

        if result == 0:
            service = common_ports.get(port, "Unknown Service")
            print(f"\nPort {port} ({service}) is OPEN")
            open_ports.append(port)

        sock.close()

    end_time = time.time()
    duration = round(end_time - start_time, 2)

    print(f"\nScan complete in {duration} seconds.\n")
    return open_ports, duration

def generate_report(target, open_ports, duration):
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report_{timestamp}.txt"

    report_lines = []
    report_lines.append(f"Vulnerability Report for {target}")
    report_lines.append("----------------------------------")

    if not open_ports:
        report_lines.append("No open ports detected.")
    else:
        for port in open_ports:
            service = common_ports.get(port, "Unknown Service")
            report_lines.append(f"Port {port} ({service}) is OPEN")

            if port in vulnerability_info:
                report_lines.append(
                    f"  Possible Vulnerability: {vulnerability_info[port]}"
                )

    report_lines.append(f"\nScan duration: {duration} seconds")

    report_lines.append("\nSecurity Recommendations:")
    report_lines.append("- Close unused ports.")
    report_lines.append("- Use firewalls.")
    report_lines.append("- Disable insecure services like Telnet.")
    report_lines.append("- Keep systems updated.")

    # Save to file
    with open(filename, "w") as file:
        for line in report_lines:
            file.write(line + "\n")

    # Show in terminal
    print("\n".join(report_lines))
    print(f"\nReport saved as {filename}")

def main():
    while True:
        print("\nSimple Vulnerability Scanner")
        print("-----------------------------")
        print("1. Scan target")
        print("2. Exit")

        choice = input("Enter your choice: ")

        if choice == "1":
            target = input("Enter target IP or domain: ")

            try:
                start_port = int(input("Enter start port: "))
                end_port = int(input("Enter end port: "))
            except:
                print("Invalid port numbers.")
                continue

            open_ports, duration = scan_ports(target, start_port, end_port)
            generate_report(target, open_ports, duration)

        elif choice == "2":
            print("Exiting scanner.")
            break

        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()

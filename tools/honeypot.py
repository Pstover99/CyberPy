"""
Name:  Parker Stover

tools/honeypot.py
-----------------
Local Port Listener / Honeypot tool.
Listens on a designated local port. When a connection is established,
sends a customizable banner, logs client information and incoming data
(such as exploit payloads or scanner checks), and saves reports to output/.

Uses only Python's standard-library `socket` and `datetime` modules.
"""

from __future__ import annotations

import socket
import time
from datetime import datetime
from pathlib import Path

from .common import OUTPUT_DIR, C, banner, kv, section, prompt_port


ALERT_LOG = OUTPUT_DIR / "honeypot_alerts.txt"


def log_alert(message: str) -> None:
    """Log honeypot alerts to the text file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    try:
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"{C.ERROR}[!] Failed to write log to file: {e}{C.RESET}")


def run_honeypot(port: int, mock_banner: str) -> None:
    """Listen on the specified port and log connection attempts."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Enable address reuse
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", port))
    except PermissionError:
        print(f"\n{C.ERROR}[!] Permission Denied. Binding to port {port} requires root privileges.{C.RESET}")
        print(f"{C.WARN}    Please select a port > 1024 if running without administrative rights.{C.RESET}")
        return
    except Exception as e:
        print(f"\n{C.ERROR}[!] Binding failed: {e}{C.RESET}")
        return

    server.listen(5)
    print(f"\n{C.GREEN}[+] Honeypot active on 0.0.0.0:{port}{C.RESET}")
    print(f"    Press {C.BOLD}Ctrl+C{C.RESET} to stop listening and return to the menu.")
    print(f"    Alerts logged to {C.BOLD}{ALERT_LOG}{C.RESET}\n")
    log_alert(f"Honeypot started on port {port}")

    try:
        while True:
            client_sock, client_addr = server.accept()
            # Prevent hanging if client doesn't send anything
            client_sock.settimeout(2.0)
            client_ip, client_port = client_addr
            alert_msg = f"CONNECTION from {client_ip}:{client_port}"
            print(f"{C.WARN}[ALERT] {alert_msg}{C.RESET}")
            log_alert(alert_msg)

            # Send banner if requested
            if mock_banner:
                try:
                    client_sock.sendall(mock_banner.encode("utf-8", errors="ignore"))
                except Exception as e:
                    print(f"  {C.ERROR}Failed sending banner: {e}{C.RESET}")

            # Read client input
            payload = ""
            try:
                data = client_sock.recv(1024)
                if data:
                    payload = data.decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                pass
            except Exception as e:
                print(f"  {C.ERROR}Error reading data: {e}{C.RESET}")

            if payload:
                print(f"  {C.KEY}Data sent:{C.RESET} {C.CYAN}{repr(payload)}{C.RESET}")
                log_alert(f"DATA from {client_ip}:{client_port} -> {payload!r}")

            try:
                client_sock.close()
            except Exception:
                pass
    except KeyboardInterrupt:
        print(f"\n{C.WARN}[-] Honeypot stopped.{C.RESET}")
        log_alert(f"Honeypot stopped on port {port}")
    finally:
        server.close()


def run() -> None:
    banner("Local Port Listener / Honeypot")
    print("Listens on a local port, logs connection attempts, and collects payloads.")
    print(f"{C.WARN}Warning: Listening on ports < 1024 (like 80, 22) requires sudo/root privileges.{C.RESET}\n")

    port = prompt_port("Enter port to listen on", default=8080)
    if port is None:
        print(f"{C.WARN}Cancelled. Returning to menu.{C.RESET}")
        return

    print("\nSelect a mock banner template:")
    print(f"  {C.KEY}1{C.RESET} SSH Service (SSH-2.0-OpenSSH_8.2p1)")
    print(f"  {C.KEY}2{C.RESET} HTTP Web Service (Apache/2.4.41)")
    print(f"  {C.KEY}3{C.RESET} Custom Banner String")
    print(f"  {C.KEY}4{C.RESET} No Banner (Silent Listener)")

    choice = input(f"{C.KEY}Choice [1-4, default 4]: {C.RESET}").strip() or "4"

    mock_banner = ""
    if choice == "1":
        mock_banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
    elif choice == "2":
        mock_banner = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache/2.4.41 (Ubuntu)\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: 53\r\n"
            "Connection: close\r\n\r\n"
            "<html><body><h1>Apache2 Default Page</h1></body></html>"
        )
    elif choice == "3":
        mock_banner = input("Enter custom banner string: ")
    else:
        mock_banner = ""

    run_honeypot(port, mock_banner)

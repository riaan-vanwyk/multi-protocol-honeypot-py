#!/usr/bin/env python3
"""
attacker_test.py

A fully-fledged attacker simulator for your FTP / SSH / Telnet honeypot.

It exercises every behavior currently implemented server-side:

  FTP  (8021)
    - USER / PASS / QUIT command flow           -> credential_stuffing
    - zero-payload instant disconnect            -> port_scan (threat category)

  SSH  (8022)
    - client ident string starting with "SSH"    -> "Protocol mismatch" -> exploit_attempt
    - several non-SSH-prefixed "auth" lines       -> credential_stuffing

  Telnet (8023)
    - the blank-line-driven login/password state machine, all the way
      through to the 4th-blank lockout message    -> credential_stuffing
    - raw IAC negotiation bytes                   -> should be silently ignored

  Cross-protocol
    - idle connection that we close ourselves     -> idle_connection
    - idle connection left until the honeypot's
      own 5s recv() timeout fires                 -> idle_connection, timed_out=True
    - rapid connections to multiple ports from
      one source IP                               -> trips check_port_scan()
      (watch the honeypot's own console for the "[ALERT] PORT SCAN DETECTED" line;
      that check is a live/console alert, not a field in the JSON log)

Usage:
    python3 attacker_test.py

Run the honeypot first, then this script in a second terminal. It's fully
interactive over stdin/stdout: pick a numbered scenario from the menu, run
everything at once, run a continuous random loop, or change the target host,
all without any command-line flags.

Run the honeypot first, then this script in a second terminal.
"""

import random
import socket
import time

HOST = "127.0.0.1"

FTP_PORT = 8021
SSH_PORT = 8022
TELNET_PORT = 8023

DEFAULT_TIMEOUT = 3.0


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def connect(port, timeout=DEFAULT_TIMEOUT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((HOST, port))
    return sock


def recv_quiet(sock, bufsize=4096):
    """Try to read whatever is waiting; return b'' on timeout/close instead of raising."""
    try:
        return sock.recv(bufsize)
    except socket.timeout:
        return b""
    except (ConnectionResetError, ConnectionAbortedError, OSError):
        return b""


def show(label, data):
    text = data.decode("utf-8", errors="ignore").strip()
    print(f"    <- [{label}] {text!r}" if text else f"    <- [{label}] (no data)")


def send(sock, label, payload: bytes):
    print(f"    -> [{label}] {payload!r}")
    sock.sendall(payload)


def banner_line(title):
    print(f"\n[*] {title}")
    print("-" * (len(title) + 4))


# --------------------------------------------------------------------------
# FTP scenarios (port 8021)
# --------------------------------------------------------------------------

def ftp_credential_stuffing():
    """USER + PASS + QUIT = 3 logged payloads -> credential_stuffing (high confidence)."""
    banner_line("FTP: simulated credential stuffing (USER / PASS / QUIT)")
    try:
        sock = connect(FTP_PORT)
        show("banner", recv_quiet(sock))

        send(sock, "cmd", b"USER admin\r\n")
        show("resp", recv_quiet(sock))

        send(sock, "cmd", b"PASS password123\r\n")
        show("resp", recv_quiet(sock))

        send(sock, "cmd", b"QUIT\r\n")
        show("resp", recv_quiet(sock))

        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] FTP test failed: {e}")


def ftp_quick_scan():
    """Connect and disconnect instantly with zero payload -> port_scan threat category."""
    banner_line("FTP: zero-payload quick disconnect (port_scan threat category)")
    try:
        sock = connect(FTP_PORT)
        show("banner", recv_quiet(sock, bufsize=256))
        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] FTP quick-scan test failed: {e}")


# --------------------------------------------------------------------------
# SSH scenarios (port 8022)
# --------------------------------------------------------------------------

def ssh_protocol_mismatch():
    """A client ident string starting with 'SSH' trips the honeypot's mismatch check."""
    banner_line("SSH: client version string triggers protocol mismatch")
    try:
        sock = connect(SSH_PORT)
        show("banner", recv_quiet(sock))

        send(sock, "cmd", b"SSH-2.0-Go-SSH-Client\r\n")
        show("resp", recv_quiet(sock))

        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] SSH protocol-mismatch test failed: {e}")


def ssh_credential_stuffing():
    """Several non-'SSH'-prefixed lines (looks like scripted auth attempts) -> credential_stuffing."""
    banner_line("SSH: simulated scripted auth attempts (credential_stuffing)")
    try:
        sock = connect(SSH_PORT)
        show("banner", recv_quiet(sock))

        for creds in (b"root:admin\r\n", b"root:123456\r\n", b"admin:admin\r\n"):
            send(sock, "cmd", creds)
            time.sleep(0.1)

        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] SSH credential-stuffing test failed: {e}")


# --------------------------------------------------------------------------
# Telnet scenarios (port 8023)
# --------------------------------------------------------------------------

def telnet_bruteforce_lockout():
    """
    Drives the honeypot's blank-line state machine:
      1st blank line seen overall -> "Enter password: "
      2nd/3rd blank line         -> "Incorrect password, please try again: "
      4th blank line             -> lockout message, connection closed

    Non-blank lines (username / password guesses) are sent as their own
    packets, separate from the blank "Enter" keystrokes, since the honeypot
    only treats a fully-blank chunk as an Enter press.
    """
    banner_line("Telnet: brute-force login flow through to lockout")
    try:
        sock = connect(TELNET_PORT)
        show("banner", recv_quiet(sock))

        send(sock, "username", b"admin\r\n")
        time.sleep(0.1)

        guesses = [b"letmein1\r\n", b"letmein2\r\n", b"letmein3\r\n"]
        for i in range(4):
            send(sock, "enter", b"\r\n")
            show("resp", recv_quiet(sock))

            if i < len(guesses):
                send(sock, "password guess", guesses[i])
                time.sleep(0.1)

        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] Telnet brute-force test failed: {e}")


def telnet_iac_negotiation():
    """Raw Telnet IAC negotiation bytes; the honeypot should silently ignore these.
    Uses a short timeout since the honeypot deliberately sends nothing back."""
    banner_line("Telnet: IAC negotiation bytes (should be ignored)")
    try:
        sock = connect(TELNET_PORT, timeout=0.5)
        show("banner", recv_quiet(sock))

        send(sock, "IAC", b"\xff\xfb\x01")   # IAC WILL ECHO
        show("resp", recv_quiet(sock, bufsize=256))

        send(sock, "IAC", b"\xff\xfd\x03")   # IAC DO SUPPRESS-GO-AHEAD
        show("resp", recv_quiet(sock, bufsize=256))

        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] Telnet IAC test failed: {e}")


# --------------------------------------------------------------------------
# Cross-protocol scenarios
# --------------------------------------------------------------------------

def idle_connection(port=SSH_PORT, sleep_s=1.5):
    """Connect, take the banner, send nothing, then close gracefully.
    0 payloads + duration > 1000ms -> idle_connection threat category."""
    banner_line(f"Idle connection on port {port} ({sleep_s}s, no payload, we close it)")
    try:
        sock = connect(port, timeout=DEFAULT_TIMEOUT + sleep_s)
        show("banner", recv_quiet(sock))
        time.sleep(sleep_s)
        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] Idle-connection test failed: {e}")


def idle_until_server_timeout(port=FTP_PORT):
    """Never send anything and never close ourselves -> the honeypot's own
    5s recv() timeout fires and force-closes the connection
    (timed_out=True, disconnect_reason='forcibly_closed_after_timeout')."""
    banner_line(f"Idle until the honeypot's own timeout fires (port {port})")
    try:
        sock = connect(port, timeout=8.0)
        show("banner", recv_quiet(sock))
        print("    [*] Waiting for the honeypot to time us out (~5s)...")
        data = recv_quiet(sock, bufsize=64)  # blocks until the honeypot times out / closes
        if data == b"":
            print("    [*] Connection closed by honeypot, as expected.")
        sock.close()
    except (ConnectionRefusedError, OSError) as e:
        print(f"    [-] Server-timeout test failed: {e}")


def port_scan_multi(ports=(FTP_PORT, SSH_PORT, TELNET_PORT), pause=0.3):
    """Connect to several ports in quick succession from one source IP.
    Should trip the honeypot's check_port_scan() (>=2 unique ports hit
    within its 5s window), since all these connections share your IP."""
    banner_line("Multi-port scan (should trip check_port_scan on the server)")
    for port in ports:
        try:
            sock = connect(port, timeout=1.0)
            show(f"banner:{port}", recv_quiet(sock, bufsize=256))
            sock.close()
        except (ConnectionRefusedError, OSError) as e:
            print(f"    [-] Could not reach port {port}: {e}")
        time.sleep(pause)


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------

# Ordered list of (label, function) so the menu prints in a sensible sequence.
SCENARIOS = [
    ("FTP: credential stuffing (USER/PASS/QUIT)", ftp_credential_stuffing),
    ("FTP: quick zero-payload scan", ftp_quick_scan),
    ("SSH: protocol mismatch", ssh_protocol_mismatch),
    ("SSH: credential stuffing", ssh_credential_stuffing),
    ("Telnet: brute-force login lockout", telnet_bruteforce_lockout),
    ("Telnet: IAC negotiation bytes", telnet_iac_negotiation),
    ("Idle connection (we close it)", idle_connection),
    ("Idle until the honeypot times us out", idle_until_server_timeout),
    ("Multi-port scan", port_scan_multi),
]


def run_all(pause_between=1.0):
    for _label, fn in SCENARIOS:
        fn()
        time.sleep(pause_between)
    print("\n[*] All scenarios complete. Check ./logs/honeypot_logs.json next to the honeypot.")


def run_forever(min_delay=5, max_delay=30):
    """Continuously fire random scenarios at random intervals -- handy for
    building up a more realistic-looking log dataset over an extended run."""
    print("[*] Continuous mode. Press Ctrl+C to stop.\n")
    try:
        while True:
            _label, fn = random.choice(SCENARIOS)
            fn()
            delay = random.uniform(min_delay, max_delay)
            print(f"[*] Sleeping {delay:.1f}s before the next simulated attacker...\n")
            time.sleep(delay)
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")


def print_menu():
    print("\n" + "=" * 60)
    print(f"  Honeypot attacker simulator   (target host: {HOST})")
    print("=" * 60)
    for i, (label, _fn) in enumerate(SCENARIOS, start=1):
        print(f"  {i:2d}) {label}")
    print(f"  {len(SCENARIOS) + 1:2d}) Run ALL scenarios once")
    print(f"  {len(SCENARIOS) + 2:2d}) Continuous random loop (Ctrl+C to stop)")
    print(f"  {len(SCENARIOS) + 3:2d}) Change target host (currently {HOST})")
    print("   0) Quit")
    print("-" * 60)


def prompt_for_host():
    global HOST
    new_host = input(f"Enter new target host [{HOST}]: ").strip()
    if new_host:
        HOST = new_host
        print(f"[*] Target host set to {HOST}")
    else:
        print("[*] Host unchanged.")


def main():
    run_all_choice = len(SCENARIOS) + 1
    loop_choice = len(SCENARIOS) + 2
    host_choice = len(SCENARIOS) + 3

    while True:
        print_menu()
        try:
            choice = input("Select an option: ").strip()
        except EOFError:
            print("\n[*] No more input. Goodbye.")
            break

        if choice == "0":
            print("[*] Goodbye.")
            break

        if not choice.isdigit():
            print("[-] Please enter a number from the menu.")
            continue

        choice = int(choice)

        if choice == run_all_choice:
            run_all()
        elif choice == loop_choice:
            run_forever()
        elif choice == host_choice:
            prompt_for_host()
        elif 1 <= choice <= len(SCENARIOS):
            _label, fn = SCENARIOS[choice - 1]
            fn()
        else:
            print("[-] Not a valid option, try again.")


if __name__ == "__main__":
    main()

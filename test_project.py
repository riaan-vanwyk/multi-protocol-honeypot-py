"""
test_project.py

Sanity tests for the Honeypot Project.
Compatible with pytest (no arguments allowed).
"""

import importlib
import sys

MODULE_NAME = "project"   # rename your honeypot file to project.py

# Try importing the honeypot module
try:
    hp = importlib.import_module(MODULE_NAME)
    print(f"[OK] Imported module '{MODULE_NAME}'")
except Exception as e:
    print(f"[FAIL] Could not import module '{MODULE_NAME}': {e}")
    sys.exit(1)


def test_protocol_mapping():
    print("Running test_protocol_mapping...")

    assert hp.GetProtocol(21) == "ftp"
    assert hp.GetProtocol(8021) == "ftp"

    assert hp.GetProtocol(22) == "ssh"
    assert hp.GetProtocol(8022) == "ssh"

    assert hp.GetProtocol(23) == "telnet"
    assert hp.GetProtocol(8023) == "telnet"

    print("[OK] Protocol mapping works correctly.")


def test_random_banner_returns_bytes():
    print("Running test_random_banner_returns_bytes...")

    banner = hp.RandomBanner(21, "192.168.1.10")
    assert isinstance(banner, bytes), "Banner must be bytes"

    banner2 = hp.RandomBanner(22, "10.0.0.5")
    assert isinstance(banner2, bytes), "Banner must be bytes"

    banner3 = hp.RandomBanner(23, "8.8.8.8")
    assert isinstance(banner3, bytes), "Banner must be bytes"

    print("[OK] RandomBanner returns byte banners.")


def test_threat_scoring_basic():
    print("Running test_threat_scoring_basic...")

    # No payloads, short duration → port scan
    cat, score, conf = hp.EvaluateThreat(0, 200)
    assert cat == "port_scan"
    assert score == 2
    assert conf == "low"

    # No payloads, long duration → idle connection
    cat, score, conf = hp.EvaluateThreat(0, 2000)
    assert cat == "idle_connection"
    assert score == 1
    assert conf == "low"

    # One payload → exploit attempt
    cat, score, conf = hp.EvaluateThreat(1, 500)
    assert cat == "exploit_attempt"
    assert score == 8
    assert conf == "medium"

    # Two payloads → credential stuffing
    cat, score, conf = hp.EvaluateThreat(2, 500)
    assert cat == "credential_stuffing"
    assert score == 12
    assert conf == "high"

    print("[OK] Threat scoring logic works correctly.")


def test_port_scan_tracking_structure_exists():
    print("Running test_port_scan_tracking_structure_exists...")

    assert hasattr(hp, "port_hits"), "port_hits dict missing"
    assert hasattr(hp, "PORT_SCAN_WINDOW"), "PORT_SCAN_WINDOW missing"
    assert hasattr(hp, "PORT_SCAN_THRESHOLD"), "PORT_SCAN_THRESHOLD missing"

    print("[OK] Port scan tracking globals exist.")


def test_main_exists():
    print("Running test_main_exists...")

    assert hasattr(hp, "main"), "main() missing"
    assert callable(hp.main), "main is not callable"

    print("[OK] main() function exists.")

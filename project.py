import socket
import sys
import threading
import time
import json
from datetime import datetime, timezone
import uuid
import random
import os
from collections import defaultdict

"""
The scope of the Project will only entail FTP, SSH, and Telnet. Nothing more, nothing less. 
"""

HOST = "0.0.0.0"
file_lock = threading.Lock()

PORT_SCAN_WINDOW = 5      # Seconds
PORT_SCAN_THRESHOLD = 2   # Number of UNIQUE ports that are hit 

# This is in line with: { IP: { (port, timestamp), (port, timestamp) } }
port_hits = defaultdict(set)
port_lock = threading.Lock()


 # The reason I am doing this is because I want to simulate a honeypot over weeks'
# time, and Grabbers / Bots will not connect unless I send back a valid header.

TELNET_BANNERS = [
    b"\r\nUbuntu 18.04.6 LTS\r\nlogin: ",
    b"\r\nUbuntu 20.04.5 LTS\r\nlogin: ",
    b"\r\nDebian GNU/Linux 10 (buster)\r\nlogin: ",
    b"\r\nDebian GNU/Linux 11 (bullseye)\r\nlogin: ",
    b"\r\nBusyBox v1.31.1 (built-in shell)\r\nlogin: ",
    b"\r\nOpenWrt 19.07.4\r\nlogin: ",
    b"\r\nOpenWrt 21.02.3\r\nlogin: ",
    b"\r\nCentOS Linux 7 (Core)\r\nlogin: ",
    b"\r\nAlpine Linux 3.17\r\nlogin: ",
]

FTP_BANNERS = [
    b"220 (vsFTPd 3.0.3)\r\n",
    b"220 ProFTPD 1.3.6 Server (Debian)\r\n",
    b"220 Pure-FTPd 1.0.49\r\n",
    b"220 Microsoft FTP Service\r\n",
    b"220 FileZilla Server 0.9.60 beta\r\n",
]

SSH_BANNERS = [
    b"SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7\r\n",
    b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    b"SSH-2.0-OpenSSH_8.4p1 Debian-5\r\n",
    b"SSH-2.0-OpenSSH_9.0p1 Debian-1\r\n",
    b"SSH-2.0-OpenSSH_7.4p1 RedHat-6\r\n",
    b"SSH-2.0-dropbear_2019.78\r\n",
    b"SSH-2.0-dropbear_2020.80\r\n",
]

def RandomBanner(port, attacker_ip):
    random.seed(attacker_ip)  # consistent per attacker

    if port in (23, 8023):
        return random.choice(TELNET_BANNERS)

    if port in (21, 8021):
        return random.choice(FTP_BANNERS)

    if port in (22, 8022):
        return random.choice(SSH_BANNERS)

    return b""  # fallback

def check_port_scan(ip_address, target_port):
    currTime = time.time()
    isScanner = False

    with port_lock:
        # 1. Voeg die huidige poort en tydstempel by vir hierdie IP
        port_hits[ip_address].add((target_port, currTime))
        
        # 2. Maak skoon: Verwyder alle hits wat ouer as 5 sekondes is
        valid_hits = {
            (port, timestamp) for port, timestamp in port_hits[ip_address]
            if currTime - timestamp <= PORT_SCAN_WINDOW
        }
        port_hits[ip_address] = valid_hits
        
        # 3. Tel hoeveel UNIEKE poorte in die laaste 5 sekondes getref is
        unique_ports = {port for port, timestamp in valid_hits}
        
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            isScanner = True
            
    return isScanner

def EvaluateThreat(PayloadsReceived, Duration):
    # PayloadsReceived is die aantal items (len) in jou payloads_received lys
    # Duration is die konneksie-duur in millisekondes
    score = 0
    category = "reconnaissance"
    
    if PayloadsReceived == 0:
        if Duration < 1000:
            category = "port_scan"
            score = 2
        else:
            category = "idle_connection"
            score = 1
    else:
        score += 5  # Punte vir aktiewe payload-stuur
        if PayloadsReceived >= 2:
            category = "credential_stuffing"
            score += 7
        else:
            category = "exploit_attempt"
            score += 3

    # Bepaal die confidence-vlak op grond van die finale score
    if score >= 10:
        confidence = "high"
    elif score >= 5:
        confidence = "medium"
    else:
        confidence = "low"

    return category, score, confidence



def GetProtocol(port):
    if port == 8021 or port == 21:
        return "ftp"
    if port == 8022 or port == 22:
        return "ssh"
    if port == 8023 or port == 23:
        return "telnet"

def HoneyPotListen(PORT, HOST):
    TIMEOUT = False;
    FTP_SOCKET = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    FTP_SOCKET.bind((HOST, PORT))
    FTP_SOCKET.listen(50)
    print(f"Listening... Host = {HOST} Port = {PORT}\n\n")
    while True:
        conn, addr = FTP_SOCKET.accept();ConnTime = time.time()
        LOG_DICT = {}
        print(f"Attacker IP + Port is {addr[0]}:{addr[1]}")
        
        client_ip = addr[0]
        if check_port_scan(client_ip, PORT):
            print(f"[ALERT] PORT SCAN DETECTED VAN {client_ip}! Getref poorte binne {PORT_SCAN_WINDOW}s.")
        
        try:
            banner_used = RandomBanner(PORT, addr[0])
            if banner_used:
                conn.send(banner_used)
        except Exception as e:
            print(f"Kon nie banner stuur nie (Bot het dalk klaar gedisconnect): {e}")
            conn.close()
            continue
        # 1. Stel die 5-sekonde timeout op die konneksie VOOR die loop begin
        conn.settimeout(5.0)
        payloads_received = []
        while True:
            try:
                # As die attacker vir 5 sekondes niks stuur nie, spring hy dadelik 
                # uit hierdie lyn uit na die 'except socket.timeout' blok toe.
                try:
                    FTP_DATA = conn.recv(5000)
                except ConnectionResetError:
                    print("Client closed the connection (RST).")
                    break
                except ConnectionAbortedError:
                    print("Client aborted the connection (WinError 10053).")
                    break


                if FTP_DATA == b"":
                    # Bot het self gedisconnect
                    TIMEOUT = False;
                    conn.close();print("Connection closed...")
                    break

                teks_payload = FTP_DATA.decode('utf-8', errors='ignore').strip()
                payloads_received.append(teks_payload)
                ### FTP code ### 
                if GetProtocol(PORT) == "ftp":
                    if teks_payload.upper().startswith("USER"):
                        conn.send(b"331 Please specify the password.\r\n")
                        continue

                    if teks_payload.upper().startswith("PASS"):
                        conn.send(b"530 Login incorrect.\r\n")
                        continue

                    if teks_payload.upper().startswith("QUIT"):
                        conn.send(b"221 Goodbye.\r\n")
                        conn.close()
                        break
                ### SSH Code ###
                if GetProtocol(PORT) == "ssh":
                    if teks_payload.upper().startswith("SSH"):
                        conn.send(b"Protocol mismatch.\r\n")
                        conn.close()
                        break;
                # print(f"Received: {teks_payload}")

                ### Telnet

                if teks_payload.strip() == "" and GetProtocol(PORT) == "telnet":
                    # ENTER gedruk
                    new_ls = [item for item in payloads_received if item != ''];
                    if len(payloads_received) - len(new_ls) == 4:
                        conn.send(b"Connection closed. Too many incorrect attempts.")
                        conn.close();
                        break;
                    if len(payloads_received) - len(new_ls) >= 2:
                        conn.send(b"Incorrect password, please try again: ")
                    else:
                        conn.send(b"Enter password: ")
                    # if ('' not in payloads_received):
                        

                

                if GetProtocol(PORT) == "telnet":
                    # Ignore Telnet negotiation bytes (IAC)
                    if FTP_DATA.startswith(b"\xff"):
                        continue


                        




            except socket.timeout:
                # 2. HIERDIE is jou "if conn.timeout()"! 
                # Die 5 sekondes is verby sonder dat ons data gekry het.
                print("5 Sekondes verby sonder data. Skop die attacker...")
                TIMEOUT = True;
                conn.close()
                break
        EndTime = time.time()
        # logging ( HOU DIE KODE BUITE DIE LOOP ) 
        # Get current UTC time
        now_utc = datetime.now(timezone.utc)

        # Format in ISO 8601 with milliseconds
        iso_timestamp = now_utc.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

        LOG_DICT["timestamp"] = iso_timestamp;
        LOG_DICT["protocol"] = GetProtocol(PORT)
        LOG_DICT["attacker_ip"] = addr[0];
        LOG_DICT["attacker_port"] = addr[1];
        LOG_DICT["target_port"] = PORT;
        LOG_DICT["banner_sent"] = banner_used.decode('utf-8', errors='ignore').strip()
        
        LOG_DICT["connection_metadata"] = dict(
            connection_id=str(uuid.uuid4()),
            timed_out = TIMEOUT,
            disconnect_reason = "forcibly_closed_after_timeout" if TIMEOUT else "attacker_closed",
            connection_duration_ms= int((EndTime - ConnTime) * 1000),
            )
        if not GetProtocol(PORT) == "telnet":
            LOG_DICT["payloads_received"] = payloads_received
        else:
            payloads_received2 = [""]  # begin met een string
            i = 0

            for item in payloads_received:
                if item != "":
                    payloads_received2[i] += item
                else:
                    payloads_received2.append("")  # maak ’n nuwe segment
                    i += 1
            # Filtreer bloot enige leë elemente uit payloads_received2 uit voor jy dit stoor
            LOG_DICT["payloads_received"] = [x for x in payloads_received2 if x != ""]


        category, score, confidence = EvaluateThreat(len(payloads_received), int((EndTime - ConnTime) * 1000))
        LOG_DICT["threat"] = dict(category=category, score=score, confidence=confidence)
        for item in LOG_DICT["payloads_received"]: print(f"Received: {item}")
        print(LOG_DICT)
        # Jy skakel dit eers om na 'n string, en dan gebruik jy .write()
        os.makedirs("./logs", exist_ok=True)
        with file_lock:
            with open("./logs/honeypot_logs.json", "a") as log_file:
                skoon_teks = json.dumps(LOG_DICT)
                log_file.write(skoon_teks + "\n")
            payloads_received = []


def main():
    global HOST;
    print("[*] Starting all 3 threads concurrently...")

    # Skep die 3 threads en koppel elke funksie aan een
    thread1 = threading.Thread(target=HoneyPotListen, args=(8021, HOST))
    thread2 = threading.Thread(target=HoneyPotListen, args=(8022, HOST))
    thread3 = threading.Thread(target=HoneyPotListen, args=(8023, HOST))

    # Maak hulle 'daemon' sodat hulle self toemaak as jy Ctrl+C druk
    thread1.daemon = True
    thread2.daemon = True
    thread3.daemon = True

    # Start al 3 threads (hulle begin nou gelyktydig in die agtergrond hardloop)
    thread1.start()
    thread2.start()
    thread3.start()

    # Hou die main program aan die lewe sodat die threads kan aanhou hardloop
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Program gestop deur gebruiker. Totsiens!")

main()

        
    

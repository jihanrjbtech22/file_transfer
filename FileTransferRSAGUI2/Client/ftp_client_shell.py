from ftplib import FTP
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

# === FTP Settings ===
FTP_PORT = 2121
FTP_USER = "user"
FTP_PASS = "12345"

# === Network Sweep ===
def check_ftp_host(ip, port=FTP_PORT, timeout=1):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return str(ip)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def sweep_for_ftp_servers(subnet="192.168.66.0/24", port=FTP_PORT, max_threads=50):
    print(f"🔍 Scanning {subnet} for FTP servers on port {port}...")
    active_hosts = []

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(check_ftp_host, ip, port) for ip in ipaddress.IPv4Network(subnet)]
        for future in futures:
            result = future.result()
            if result:
                print(f"✅ Found FTP server: {result}:{port}")
                active_hosts.append(result)

    return active_hosts

# === Scan & Connect ===
servers = sweep_for_ftp_servers()
if not servers:
    print("❌ No FTP servers found on the local network.")
    exit()

print("\nAvailable FTP Servers:")
for idx, ip in enumerate(servers):
    print(f"[{idx}] {ip}")

choice = input("Select a server by index: ").strip()
try:
    selected_ip = servers[int(choice)]
except (IndexError, ValueError):
    print("❌ Invalid selection.")
    exit()

ftp = FTP()
ftp.connect(selected_ip, FTP_PORT)
ftp.login(FTP_USER, FTP_PASS)
print(f"🌐 Connected to FTP Server at {selected_ip}")

# === RSA Key Handling ===
if os.path.exists("private.pem") and os.path.exists("public.pem"):
    print("🔑 RSA keys already exist. Skipping generation.")
else:
    key = RSA.generate(2048)
    with open("private.pem", "wb") as f:
        f.write(key.export_key())
    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())
    print("🔐 RSA key pair generated.")

print("Type 'help' to see available commands.")

# === FTP Commands ===
def list_files():
    ftp.retrlines("LIST")

def encrypt_file(input_file, output_file, pub_key_path="public.pem"):
    with open(pub_key_path, "rb") as f:
        pub_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(pub_key)
    with open(input_file, "rb") as f:
        data = f.read()
    chunk_size = 190
    encrypted_data = b"".join(cipher.encrypt(data[i:i+chunk_size]) for i in range(0, len(data), chunk_size))
    with open(output_file, "wb") as f:
        f.write(encrypted_data)

def upload_file(filename):
    if not os.path.exists(filename):
        print(f"❌ File '{filename}' not found.")
        return
    encrypted_path = f"{filename}.enc"
    encrypt_file(filename, encrypted_path)
    try:
        ftp.set_debuglevel(2)
        host, port = ftp.makepasv()
        print(f"Host:{host}")
        ftp.voidcmd("TYPE I")
        conn = ftp.transfercmd(f"STOR {os.path.basename(encrypted_path)}")
        with open(encrypted_path, "rb") as f:
            while (block := f.read(1024)):
                conn.send(block)
        conn.close()
        ftp.voidresp()
        print(f"🔐 Encrypted & Uploaded: {encrypted_path}")
    except Exception as e:
        print(f"❌ Error: {e}")

def decrypt_file(input_file, output_file, priv_key_path="private.pem"):
    with open(priv_key_path, "rb") as f:
        priv_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(priv_key)
    with open(input_file, "rb") as f:
        encrypted_data = f.read()
    chunk_size = 256
    decrypted_data = b"".join(cipher.decrypt(encrypted_data[i:i+chunk_size]) for i in range(0, len(encrypted_data), chunk_size))
    with open(output_file, "wb") as f:
        f.write(decrypted_data)

def download_file(filename):
    try:
        ftp.set_debuglevel(2)
        host, port = ftp.makepasv()
        print(f"Host:{host}")
        ftp.voidcmd("TYPE I")
        conn = ftp.transfercmd(f"RETR {filename}")
        downloads_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(downloads_dir, exist_ok=True)
        encrypted_path = os.path.join(downloads_dir, os.path.basename(filename))
        with open(encrypted_path, "wb") as f:
            while (block := conn.recv(1024)):
                f.write(block)
        conn.close()
        ftp.voidresp()
        decrypted_path = encrypted_path.replace(".enc", "")
        decrypt_file(encrypted_path, decrypted_path)
        print(f"📥 Encrypted downloaded ➜ {encrypted_path}")
        print(f"🔓 Decrypted saved ➜ {decrypted_path}")

    except Exception as e:
        print(f"❌ Error: {e}")

def delete_file(filename):
    try:
        ftp.delete(filename)
        print(f"🗑️ Deleted: {filename}")
    except Exception as e:
        print(f"❌ Error: {e}")

def make_directory(folder_name):
    try:
        ftp.mkd(folder_name)
        print(f"📂 Created folder: {folder_name}")
    except Exception as e:
        print(f"❌ Error: {e}")

def delete_directory(folder_name):
    try:
        ftp.rmd(folder_name)
        print(f"🗑️ Deleted folder: {folder_name}")
    except Exception as e:
        print(f"❌ Error: {e}")

def change_directory(folder_name):
    try:
        ftp.cwd(folder_name)
        print(f"📌 Changed to: {ftp.pwd()}")
    except Exception as e:
        print(f"❌ Error: {e}")

def print_working_directory():
    print(f"📍 Current dir: {ftp.pwd()}")

def show_help():
    print("""
Available commands:
    ls                    - List files and directories
    upload <filename>     - Upload file to server
    download <filename>   - Download file from server
    delete <filename>     - Delete file on server
    mkdir <foldername>    - Create a new folder
    rmdir <foldername>    - Remove a folder (must be empty)
    cd <foldername>       - Change directory
    pwd                   - Show current directory
    help                  - Show this help menu
    exit                  - Exit the FTP shell
""")

# === Interactive Shell ===
while True:
    cmd = input("ftp> ").strip()
    if not cmd:
        continue
    parts = cmd.split()
    command = parts[0]

    if command == "ls":
        list_files()
    elif command == "upload" and len(parts) == 2:
        upload_file(parts[1])
    elif command == "download" and len(parts) == 2:
        download_file(parts[1])
    elif command == "delete" and len(parts) == 2:
        delete_file(parts[1])
    elif command == "mkdir" and len(parts) == 2:
        make_directory(parts[1])
    elif command == "rmdir" and len(parts) == 2:
        delete_directory(parts[1])
    elif command == "cd" and len(parts) == 2:
        change_directory(parts[1])
    elif command == "pwd":
        print_working_directory()
    elif command == "help":
        show_help()
    elif command == "exit":
        print("👋 Disconnecting and exiting...")
        ftp.quit()
        break
    else:
        print("❓ Unknown command. Type 'help' to see options.")

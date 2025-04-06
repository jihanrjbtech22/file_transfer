from ftplib import FTP
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os
import re

# === FTP Credentials ===
FTP_HOST = "192.168.66.3"
FTP_PORT = 2121
FTP_USER = "user"
FTP_PASS = "12345"

# === Connect once and reuse ===
ftp = FTP()
ftp.connect(FTP_HOST, FTP_PORT)
ftp.login(FTP_USER, FTP_PASS)

print("🌐 Connected to FTP Server.")

# Generate key pair
key = RSA.generate(2048)

private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

print("🔐 RSA key pair generated.")
print("Type 'help' to see available commands.")


def get_pasv_data_port():
    # Enter passive mode and capture the server response
    response = ftp.sendcmd("PASV")
    print(f"📡 PASV response: {response}")

    # Extract the 6 numbers from the response
    match = re.search(r"\((\d+,\d+,\d+,\d+,\d+,\d+)\)", response)
    if not match:
        raise Exception("⚠️ Could not parse PASV response")

    numbers = list(map(int, match.group(1).split(",")))
    p1, p2 = numbers[-2], numbers[-1]
    port = p1 * 256 + p2

    print(f"📦 Data Connection Port: {port}")
    return port

# === Command Handlers ===
def list_files():
    ftp.retrlines("LIST")


def encrypt_file(input_file, output_file, pub_key_path="public.pem"):
    with open(pub_key_path, "rb") as f:
        pub_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(pub_key)

    with open(input_file, "rb") as f:
        data = f.read()

    # Encrypt in chunks since RSA can’t handle large data at once
    chunk_size = 190  # Max for 2048-bit RSA w/ PKCS1_OAEP
    encrypted_data = b""
    for i in range(0, len(data), chunk_size):
        encrypted_data += cipher.encrypt(data[i:i+chunk_size])

    with open(output_file, "wb") as f:
        f.write(encrypted_data)

def upload_file(filename):
    if not os.path.exists(filename):
        print(f"❌ File '{filename}' not found.")
        return

    encrypted_path = f"{filename}.enc"
    encrypt_file(filename, encrypted_path)

    try:
        data_port = get_pasv_data_port()
        ftp.voidcmd("TYPE I")
        conn = ftp.transfercmd(f"STOR {os.path.basename(encrypted_path)}")

        with open(encrypted_path, "rb") as f:
            while True:
                block = f.read(1024)
                if not block:
                    break
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

    chunk_size = 256  # For 2048-bit RSA
    decrypted_data = b""
    for i in range(0, len(encrypted_data), chunk_size):
        decrypted_data += cipher.decrypt(encrypted_data[i:i+chunk_size])

    with open(output_file, "wb") as f:
        f.write(decrypted_data)

def download_file(filename):
    try:
        data_port = get_pasv_data_port()
        ftp.voidcmd("TYPE I")
        conn = ftp.transfercmd(f"RETR {filename}")

        downloads_dir = os.path.join(os.getcwd(), "downloads")
        os.makedirs(downloads_dir, exist_ok=True)

        encrypted_path = os.path.join(downloads_dir, os.path.basename(filename))
        with open(encrypted_path, "wb") as f:
            while True:
                block = conn.recv(1024)
                if not block:
                    break
                f.write(block)

        conn.close()
        ftp.voidresp()

        # Now decrypt
        decrypted_path = encrypted_path.replace(".enc", "")
        decrypt_file(encrypted_path, decrypted_path)

        print(f"📥 Encrypted file downloaded ➜ {encrypted_path}")
        print(f"🔓 Decrypted file saved ➜ {decrypted_path}")
    except Exception as e:
        print(f"❌ Error: {e}")



def delete_file(filename):
    try:
        ftp.delete(filename)
        print(f"🗑️ Deleted file: {filename}")
    except Exception as e:
        print(f"❌ Error: {e}")

def make_directory(folder_name):
    try:
        ftp.mkd(folder_name)
        print(f"📂 Folder created: {folder_name}")
    except Exception as e:
        print(f"❌ Error: {e}")

def delete_directory(folder_name):
    try:
        ftp.rmd(folder_name)
        print(f"🗑️ Folder deleted: {folder_name}")
    except Exception as e:
        print(f"❌ Error: {e}")

def change_directory(folder_name):
    try:
        ftp.cwd(folder_name)
        print(f"📌 Changed to directory: {ftp.pwd()}")
    except Exception as e:
        print(f"❌ Error: {e}")

def print_working_directory():
    print(f"📍 Current directory: {ftp.pwd()}")

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

# === Shell Loop ===
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

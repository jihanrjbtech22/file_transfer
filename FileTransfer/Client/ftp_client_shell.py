from ftplib import FTP
import os

# === FTP Credentials ===
FTP_HOST = "192.168.65.6"
FTP_PORT = 2121
FTP_USER = "user"
FTP_PASS = "12345"

# === Connect once and reuse ===
ftp = FTP()
ftp.connect(FTP_HOST, FTP_PORT)
ftp.login(FTP_USER, FTP_PASS)

print("🌐 Connected to FTP Server.")
print("Type 'help' to see available commands.")

# === Command Handlers ===
def list_files():
    ftp.retrlines("LIST")

def upload_file(filename):
    if not os.path.exists(filename):
        print(f"❌ File '{filename}' not found.")
        return
    with open(filename, "rb") as f:
        ftp.storbinary(f"STOR {os.path.basename(filename)}", f)
    print(f"✅ Uploaded: {filename}")

def download_file(filename):
    try:
        with open(filename, "wb") as f:
            ftp.retrbinary(f"RETR {filename}", f.write)
        print(f"📥 Downloaded: {filename}")
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

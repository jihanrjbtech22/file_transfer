import ftplib
import os
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

FTP_USER = "ftpuser"
FTP_PASS = "ftp_password"

def encrypt_file(input_file):
    with open("rsa_keys/server_public.pem", "rb") as key_file:
        public_key = RSA.import_key(key_file.read())

    cipher = PKCS1_OAEP.new(public_key)

    with open(input_file, "rb") as f:
        file_data = f.read()

    encrypted_data = cipher.encrypt(file_data)

    encrypted_file = input_file + ".enc"
    with open(encrypted_file, "wb") as f:
        f.write(encrypted_data)

    print(f"✅ File '{input_file}' encrypted as '{encrypted_file}'")
    return encrypted_file

def send_file(server_ip, file_path):
    encrypted_file = encrypt_file(file_path)

    ftp = ftplib.FTP(server_ip)
    ftp.login(FTP_USER, FTP_PASS)
    ftp.cwd("uploads")

    with open(encrypted_file, "rb") as f:
        ftp.storbinary(f"STOR {os.path.basename(encrypted_file)}", f)

    print(f"✅ Encrypted file '{encrypted_file}' sent to {server_ip}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py <Server_IP> <File_Path>")
        sys.exit(1)

    send_file(sys.argv[1], sys.argv[2])

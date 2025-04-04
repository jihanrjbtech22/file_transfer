import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from ftplib import FTP

# ---------- SETTINGS ----------
server_ip = "192.168.x.x"   # Change this to your Linux IP
ftp_user = "ftpuser"
ftp_pass = "yourpassword"
file_to_encrypt = "../abc.txt"
server_public_key_path = "../Server/public.pem"
encrypted_file_path = "../Files/abc.txt.enc"
# ------------------------------

# Step 1: Load public key
with open(server_public_key_path, "rb") as f:
    key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(key)

# Step 2: Encrypt file
with open(file_to_encrypt, "rb") as f:
    plaintext = f.read()

# Split into chunks for RSA encryption
chunk_size = 190  # RSA max size with padding
chunks = [plaintext[i:i+chunk_size] for i in range(0, len(plaintext), chunk_size)]
ciphertext = b''.join([cipher.encrypt(chunk) for chunk in chunks])

with open(encrypted_file_path, "wb") as f:
    f.write(ciphertext)

print(f"File encrypted and saved as {encrypted_file_path}")

# Step 3: Send via FTP
ftp = FTP(server_ip)
ftp.login(ftp_user, ftp_pass)

with open(encrypted_file_path, "rb") as f:
    ftp.storbinary(f"STOR {os.path.basename(encrypted_file_path)}", f)

ftp.quit()
print("Encrypted file sent to server.")

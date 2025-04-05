import os
import ftplib
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

UPLOAD_DIR = "uploads"
RECEIVED_DIR = "received_files"

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(RECEIVED_DIR, exist_ok=True)

def decrypt_file(encrypted_file):
    with open("rsa_keys/private_key.pem", "rb") as key_file:
        private_key = RSA.import_key(key_file.read())

    cipher = PKCS1_OAEP.new(private_key)

    with open(encrypted_file, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = cipher.decrypt(encrypted_data)

    decrypted_file = os.path.join(RECEIVED_DIR, os.path.basename(encrypted_file).replace(".enc", ".txt"))
    with open(decrypted_file, "wb") as f:
        f.write(decrypted_data)

    os.remove(encrypted_file)
    print(f"✅ Decrypted file saved as {decrypted_file}")

if __name__ == "__main__":
    print("🔄 Server is watching for incoming files...")
    while True:
        for file in os.listdir(UPLOAD_DIR):
            if file.endswith(".enc"):
                decrypt_file(os.path.join(UPLOAD_DIR, file))

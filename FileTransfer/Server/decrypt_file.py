from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# ---------- SETTINGS ----------
private_key_path = "../Server/private.pem"
encrypted_file = "../Files/abc_encrypted.txt.enc"  # Name received from client
decrypted_file = "../Files/abc_decrypted.txt"
# ------------------------------

# Step 1: Load private key
with open(private_key_path, "rb") as f:
    private_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(private_key)

# Step 2: Read and decrypt
with open(encrypted_file, "rb") as f:
    encrypted_data = f.read()

chunk_size = 256  # For 2048-bit RSA
chunks = [encrypted_data[i:i+chunk_size] for i in range(0, len(encrypted_data), chunk_size)]
decrypted_data = b''.join([cipher.decrypt(chunk) for chunk in chunks])

# Step 3: Save decrypted file
with open(decrypted_file, "wb") as f:
    f.write(decrypted_data)

print(f"Decrypted file saved as {decrypted_file}")

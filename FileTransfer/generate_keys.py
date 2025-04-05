from Crypto.PublicKey import RSA
import os

def generate_keys():
    os.makedirs("rsa_keys", exist_ok=True)

    key = RSA.generate(2048)

    with open("rsa_keys/private_key.pem", "wb") as private_file:
        private_file.write(key.export_key())

    with open("rsa_keys/public_key.pem", "wb") as public_file:
        public_file.write(key.publickey().export_key())

    print("✅ RSA Keys generated!")

if __name__ == "__main__":
    generate_keys()

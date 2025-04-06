# GUI for FTP Client with Server Discovery and File Operations
import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from ftplib import FTP
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

# === FTP Settings ===
FTP_PORT = 2121
FTP_USER = "user"
FTP_PASS = "12345"

class FTPClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure FTP Client")
        self.ftp = None
        self.setup_gui()

    def setup_gui(self):
        self.frame = ttk.Frame(self.root, padding=10)
        self.frame.grid(row=0, column=0, sticky="nsew")

        self.server_list = tk.Listbox(self.frame, height=5, width=40)
        self.server_list.grid(row=0, column=0, columnspan=2)

        self.scan_button = ttk.Button(self.frame, text="Scan for Servers", command=self.scan_servers)
        self.scan_button.grid(row=1, column=0, pady=5)

        self.connect_button = ttk.Button(self.frame, text="Connect", command=self.connect_to_server)
        self.connect_button.grid(row=1, column=1, pady=5)

        self.upload_button = ttk.Button(self.frame, text="Upload File", command=self.upload_file, state="disabled")
        self.upload_button.grid(row=2, column=0, pady=5)

        self.download_button = ttk.Button(self.frame, text="Download File", command=self.download_file, state="disabled")
        self.download_button.grid(row=2, column=1, pady=5)

        self.file_list = tk.Listbox(self.frame, height=10, width=60)
        self.file_list.grid(row=3, column=0, columnspan=2, pady=5)

        self.status = tk.Label(self.frame, text="Status: Ready", anchor="w")
        self.status.grid(row=4, column=0, columnspan=2, sticky="we")

    def scan_servers(self):
        self.status.config(text="Status: Scanning network...")
        self.server_list.delete(0, tk.END)
        self.root.update_idletasks()

        def check_ftp_host(ip):
            try:
                with socket.create_connection((str(ip), FTP_PORT), timeout=0.5):
                    return str(ip)
            except:
                return None

        subnet = "192.168.66.0/24"
        active_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_ftp_host, ip) for ip in ipaddress.IPv4Network(subnet)]
            for future in futures:
                result = future.result()
                if result:
                    self.server_list.insert(tk.END, result)
                    active_hosts.append(result)

        self.status.config(text="Status: Scan complete")

    def connect_to_server(self):
        selection = self.server_list.curselection()
        if not selection:
            messagebox.showerror("Error", "No server selected")
            return

        ip = self.server_list.get(selection[0])
        try:
            self.ftp = FTP()
            self.ftp.connect(ip, FTP_PORT)
            self.ftp.login(FTP_USER, FTP_PASS)
            self.status.config(text=f"Connected to {ip}")
            self.upload_button.config(state="normal")
            self.download_button.config(state="normal")
            self.list_files()
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))

    def list_files(self):
        self.file_list.delete(0, tk.END)
        self.ftp.retrlines("NLST", lambda name: self.file_list.insert(tk.END, name))

    def encrypt_file(self, input_file, output_file):
        with open("public.pem", "rb") as f:
            pub_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(pub_key)
        with open(input_file, "rb") as f:
            data = f.read()
        encrypted_data = b"".join(cipher.encrypt(data[i:i+190]) for i in range(0, len(data), 190))
        with open(output_file, "wb") as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_file, output_file):
        with open("private.pem", "rb") as f:
            priv_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(priv_key)
        with open(input_file, "rb") as f:
            encrypted_data = f.read()
        decrypted_data = b"".join(cipher.decrypt(encrypted_data[i:i+256]) for i in range(0, len(encrypted_data), 256))
        with open(output_file, "wb") as f:
            f.write(decrypted_data)

    def upload_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        encrypted_path = f"{file_path}.enc"
        self.encrypt_file(file_path, encrypted_path)
        with open(encrypted_path, "rb") as f:
            self.ftp.storbinary(f"STOR {os.path.basename(encrypted_path)}", f)

        self.status.config(text=f"Uploaded {os.path.basename(encrypted_path)}")
        self.list_files()

    def download_file(self):
        selection = self.file_list.curselection()
        if not selection:
            messagebox.showerror("Error", "No file selected")
            return

        filename = self.file_list.get(selection[0])
        if not filename.endswith(".enc"):
            messagebox.showinfo("Note", "Only .enc files can be decrypted")
            return

        save_path = filedialog.asksaveasfilename(defaultextension=".bin")
        if not save_path:
            return

        encrypted_path = save_path + ".enc"
        with open(encrypted_path, "wb") as f:
            self.ftp.retrbinary(f"RETR {filename}", f.write)

        self.decrypt_file(encrypted_path, save_path)
        self.status.config(text=f"Downloaded and decrypted to {save_path}")


if __name__ == "__main__":
    if not os.path.exists("public.pem") or not os.path.exists("private.pem"):
        key = RSA.generate(2048)
        with open("private.pem", "wb") as f:
            f.write(key.export_key())
        with open("public.pem", "wb") as f:
            f.write(key.publickey().export_key())

    root = tk.Tk()
    app = FTPClientApp(root)
    root.mainloop()

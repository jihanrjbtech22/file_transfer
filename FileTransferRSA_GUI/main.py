import os
import ipaddress
import socket
from ftplib import FTP
from concurrent.futures import ThreadPoolExecutor
from tkinter import *
from tkinter import filedialog, messagebox
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from tkinter import simpledialog


FTP_PORT = 2121
FTP_USER = "user"
FTP_PASS = "12345"
CHUNK_SIZE = 1024

class FTPClientApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted FTP Client")
        self.root.geometry("600x400")
        self.ftp = None
        self.servers = []

        self.create_widgets()

    def create_widgets(self):
        self.scan_btn = Button(self.root, text="Start Client", command=self.scan_servers)
        self.scan_btn.pack(pady=5)

        self.server_var = StringVar()
        self.server_menu = OptionMenu(self.root, self.server_var, ())
        self.server_menu.pack(pady=5)

        self.connect_btn = Button(self.root, text="Connect", command=self.connect_server)
        self.connect_btn.pack(pady=5)

        self.file_list = Listbox(self.root, width=60, height=10)
        self.file_list.pack(pady=10)

        self.upload_btn = Button(self.root, text="Upload File", command=self.upload_file)
        self.download_btn = Button(self.root, text="Download File", command=self.download_file)
        self.delete_btn = Button(self.root, text="Delete File", command=self.delete_file)

        self.upload_btn.pack(pady=2)
        self.download_btn.pack(pady=2)
        self.delete_btn.pack(pady=2)
        
        self.folder_frame = Frame(self.root)
        self.folder_frame.pack(pady=5)

        self.mkdir_btn = Button(self.folder_frame, text="Create Folder", command=self.create_folder)
        self.mkdir_btn.pack(side=LEFT, padx=2)

        self.back_btn = Button(self.folder_frame, text="⬅️ Back", command=self.go_back)
        self.back_btn.pack(side=LEFT, padx=2)

        self.open_btn = Button(self.folder_frame, text="Open Folder", command=self.open_folder)
        self.open_btn.pack(side=LEFT, padx=2)

        self.path_label = Label(self.root, text="📍 Current Path: /")
        self.path_label.pack(pady=5)


    def scan_servers(self):
        self.servers = self.sweep_for_ftp_servers("192.168.66.0/24")
        if not self.servers:
            messagebox.showerror("No Servers", "No FTP servers found.")
            return

        self.server_var.set(self.servers[0])
        menu = self.server_menu["menu"]
        menu.delete(0, "end")
        for ip in self.servers:
            menu.add_command(label=ip, command=lambda value=ip: self.server_var.set(value))
        messagebox.showinfo("Scan Complete", f"Found {len(self.servers)} server(s).")

    def sweep_for_ftp_servers(self, subnet="192.168.66.0/24", port=FTP_PORT):
        def check_ftp_host(ip):
            try:
                with socket.create_connection((str(ip), port), timeout=1):
                    return str(ip)
            except Exception:
                return None

        active_hosts = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_ftp_host, ip) for ip in ipaddress.IPv4Network(subnet)]
            for future in futures:
                result = future.result()
                if result:
                    active_hosts.append(result)
        return active_hosts

    def connect_server(self):
        ip = self.server_var.get()
        if not ip:
            messagebox.showerror("No IP", "Select a server IP first.")
            return
        try:
            self.ftp = FTP()
            self.ftp.connect(ip, FTP_PORT)
            self.ftp.login(FTP_USER, FTP_PASS)
            self.generate_rsa_keys()
            self.refresh_file_list()
            messagebox.showinfo("Connected", f"Connected to FTP server at {ip}")
        except Exception as e:
            messagebox.showerror("Connection Failed", str(e))

    def refresh_file_list(self):
        if self.ftp:
            self.file_list.delete(0, END)
            self.update_current_path()
            try:
                entries = []
                self.ftp.retrlines("LIST", entries.append)
                for entry in entries:
                    parts = entry.split()
                    name = parts[-1]
                    if entry.upper().startswith("D"):  # likely a DIR
                        self.file_list.insert(END, f"{name}/")
                    else:
                        self.file_list.insert(END, name)
            except Exception as e:
                messagebox.showerror("Error", str(e))


    def generate_rsa_keys(self):
        if os.path.exists("private.pem") and os.path.exists("public.pem"):
            return
        key = RSA.generate(2048)
        with open("private.pem", "wb") as f:
            f.write(key.export_key())
        with open("public.pem", "wb") as f:
            f.write(key.publickey().export_key())

    def encrypt_file(self, input_file, output_file):
        with open("public.pem", "rb") as f:
            pub_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(pub_key)
        with open(input_file, "rb") as f:
            data = f.read()
        encrypted = b"".join(cipher.encrypt(data[i:i+190]) for i in range(0, len(data), 190))
        with open(output_file, "wb") as f:
            f.write(encrypted)

    def decrypt_file(self, input_file, output_file):
        with open("private.pem", "rb") as f:
            priv_key = RSA.import_key(f.read())
        cipher = PKCS1_OAEP.new(priv_key)
        with open(input_file, "rb") as f:
            encrypted = f.read()
        decrypted = b"".join(cipher.decrypt(encrypted[i:i+256]) for i in range(0, len(encrypted), 256))
        with open(output_file, "wb") as f:
            f.write(decrypted)

    def upload_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        encrypted_path = filepath + ".enc"
        self.encrypt_file(filepath, encrypted_path)
        with open(encrypted_path, "rb") as f:
            self.ftp.storbinary(f"STOR {os.path.basename(encrypted_path)}", f)
        messagebox.showinfo("Upload", "File uploaded (encrypted).")
        self.refresh_file_list()

    def download_file(self):
        selection = self.file_list.get(ACTIVE)
        if not selection.endswith(".enc"):
            messagebox.showwarning("Invalid", "Select an encrypted (.enc) file to download.")
            return
        local_enc = os.path.join(os.getcwd(), "downloads", selection)
        os.makedirs(os.path.dirname(local_enc), exist_ok=True)
        with open(local_enc, "wb") as f:
            self.ftp.retrbinary(f"RETR {selection}", f.write)
        decrypted = local_enc.replace(".enc", "")
        self.decrypt_file(local_enc, decrypted)
        messagebox.showinfo("Download", f"Downloaded ➜ {local_enc}\nDecrypted ➜ {decrypted}")

    def delete_file(self):
        filename = self.file_list.get(ACTIVE)
        if not filename:
            return
        self.ftp.delete(filename)
        self.refresh_file_list()
        messagebox.showinfo("Deleted", f"{filename} deleted from server.")
        
    def update_current_path(self):
        if self.ftp:
            path = self.ftp.pwd()
            self.path_label.config(text=f"📍 Current Path: {path}")

    def create_folder(self):
        folder_name = simpledialog.askstring("Folder Name", "Enter folder name:")
        if folder_name:
            try:
                self.ftp.mkd(folder_name)
                self.refresh_file_list()
                messagebox.showinfo("Folder Created", f"Created folder: {folder_name}")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def go_back(self):
        try:
            self.ftp.cwd("..")
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def open_folder(self):
        selected = self.file_list.get(ACTIVE)
        try:
            self.ftp.cwd(selected)
            self.refresh_file_list()
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open folder: {selected}\n{str(e)}")


# === Run the GUI App ===
if __name__ == "__main__":
    root = Tk()
    app = FTPClientApp(root)
    root.mainloop()

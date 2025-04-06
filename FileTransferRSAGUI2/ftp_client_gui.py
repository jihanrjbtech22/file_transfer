import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext, simpledialog
from ftplib import FTP
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import threading

# === Constants ===
FTP_PORT = 2121
FTP_USER = "user"
FTP_PASS = "12345"
BG_COLOR = "#f0f0f0"
BUTTON_COLOR = "#e1e1e1"
ACTIVE_COLOR = "#d0d0d0"
TEXT_COLOR = "#333333"
ACCENT_COLOR = "#4a6fa5"

class FTPClientGUI:
    def __init__(self, root):
        self.root = root
        self.ftp = None
        self.current_dir = ""
        self.server_ip = ""
        self.setup_ui()
        self.check_rsa_keys()
        
    def setup_ui(self):
        # Main window configuration
        self.root.title("Secure FTP Client")
        self.root.geometry("900x700")
        self.root.configure(bg=BG_COLOR)
        
        # Configure grid weights
        self.root.grid_rowconfigure(2, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Header frame
        header_frame = tk.Frame(self.root, bg=ACCENT_COLOR, padx=10, pady=10)
        header_frame.grid(row=0, column=0, sticky="ew")
        
        self.title_label = tk.Label(
            header_frame, 
            text="Secure FTP Client", 
            bg=ACCENT_COLOR, 
            fg="white", 
            font=("Arial", 16, "bold")
        )
        self.title_label.pack(side="left")
        
        self.connection_label = tk.Label(
            header_frame, 
            text="Not Connected", 
            bg=ACCENT_COLOR, 
            fg="#ffdddd", 
            font=("Arial", 10)
        )
        self.connection_label.pack(side="right")
        
        # Connection frame
        connection_frame = tk.Frame(self.root, bg=BG_COLOR, padx=10, pady=10)
        connection_frame.grid(row=1, column=0, sticky="ew")
        
        # Server selection
        tk.Label(
            connection_frame, 
            text="Server IP:", 
            bg=BG_COLOR
        ).grid(row=0, column=0, sticky="w")
        
        self.server_var = tk.StringVar()
        self.server_combobox = ttk.Combobox(
            connection_frame, 
            textvariable=self.server_var, 
            width=25
        )
        self.server_combobox.grid(row=0, column=1, sticky="w", padx=5)
        
        scan_btn = tk.Button(
            connection_frame, 
            text="Scan Network", 
            command=self.scan_network,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        scan_btn.grid(row=0, column=2, padx=5)
        
        connect_btn = tk.Button(
            connection_frame, 
            text="Connect", 
            command=self.connect_to_server,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        connect_btn.grid(row=0, column=3, padx=5)
        
        disconnect_btn = tk.Button(
            connection_frame, 
            text="Disconnect", 
            command=self.disconnect_from_server,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        disconnect_btn.grid(row=0, column=4, padx=5)
        
        # Main content area
        content_frame = tk.Frame(self.root, bg=BG_COLOR)
        content_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 10))
        content_frame.grid_rowconfigure(0, weight=1)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_columnconfigure(1, weight=1)
        
        # Left panel - Local files
        local_frame = tk.LabelFrame(
            content_frame, 
            text="Local Files", 
            bg=BG_COLOR, 
            padx=5, 
            pady=5
        )
        local_frame.grid(row=0, column=0, sticky="nsew", padx=5)
        local_frame.grid_rowconfigure(1, weight=1)
        local_frame.grid_columnconfigure(0, weight=1)
        
        # Local path navigation
        local_nav_frame = tk.Frame(local_frame, bg=BG_COLOR)
        local_nav_frame.grid(row=0, column=0, sticky="ew")
        
        self.local_path_var = tk.StringVar(value=os.getcwd())
        local_path_entry = tk.Entry(
            local_nav_frame, 
            textvariable=self.local_path_var,
            width=40
        )
        local_path_entry.grid(row=0, column=0, sticky="ew")
        
        browse_btn = tk.Button(
            local_nav_frame, 
            text="Browse", 
            command=self.browse_local,
            width=8,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        browse_btn.grid(row=0, column=1, padx=5)
        
        # Local file list
        self.local_tree = ttk.Treeview(
            local_frame, 
            columns=("name", "size"), 
            show="headings",
            selectmode="browse"
        )
        self.local_tree.heading("name", text="Name")
        self.local_tree.heading("size", text="Size")
        self.local_tree.column("name", width=200)
        self.local_tree.column("size", width=80)
        
        scroll_local_y = ttk.Scrollbar(
            local_frame, 
            orient="vertical", 
            command=self.local_tree.yview
        )
        scroll_local_x = ttk.Scrollbar(
            local_frame, 
            orient="horizontal", 
            command=self.local_tree.xview
        )
        self.local_tree.configure(
            yscrollcommand=scroll_local_y.set,
            xscrollcommand=scroll_local_x.set
        )
        
        self.local_tree.grid(row=1, column=0, sticky="nsew")
        scroll_local_y.grid(row=1, column=1, sticky="ns")
        scroll_local_x.grid(row=2, column=0, sticky="ew")
        
        # Bind double-click event
        self.local_tree.bind("<Double-1>", self.on_local_double_click)
        
        # Local file buttons
        local_btn_frame = tk.Frame(local_frame, bg=BG_COLOR)
        local_btn_frame.grid(row=3, column=0, sticky="ew", pady=(5, 0))
        
        upload_btn = tk.Button(
            local_btn_frame, 
            text="Upload", 
            command=self.upload_file,
            width=10,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        upload_btn.pack(side="left", padx=2)
        
        # Right panel - Remote files
        remote_frame = tk.LabelFrame(
            content_frame, 
            text="Remote Files", 
            bg=BG_COLOR, 
            padx=5, 
            pady=5
        )
        remote_frame.grid(row=0, column=1, sticky="nsew", padx=5)
        remote_frame.grid_rowconfigure(1, weight=1)
        remote_frame.grid_columnconfigure(0, weight=1)
        
        # Remote path navigation
        remote_nav_frame = tk.Frame(remote_frame, bg=BG_COLOR)
        remote_nav_frame.grid(row=0, column=0, sticky="ew")
        
        self.remote_path_var = tk.StringVar(value="/")
        remote_path_entry = tk.Entry(
            remote_nav_frame, 
            textvariable=self.remote_path_var,
            width=40
        )
        remote_path_entry.grid(row=0, column=0, sticky="ew")
        
        refresh_btn = tk.Button(
            remote_nav_frame, 
            text="Refresh", 
            command=self.refresh_remote,
            width=8,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        refresh_btn.grid(row=0, column=1, padx=5)
        
        # Remote file list
        self.remote_tree = ttk.Treeview(
            remote_frame, 
            columns=("name", "size"), 
            show="headings",
            selectmode="browse"
        )
        self.remote_tree.heading("name", text="Name")
        self.remote_tree.heading("size", text="Size")
        self.remote_tree.column("name", width=200)
        self.remote_tree.column("size", width=80)
        
        scroll_remote_y = ttk.Scrollbar(
            remote_frame, 
            orient="vertical", 
            command=self.remote_tree.yview
        )
        scroll_remote_x = ttk.Scrollbar(
            remote_frame, 
            orient="horizontal", 
            command=self.remote_tree.xview
        )
        self.remote_tree.configure(
            yscrollcommand=scroll_remote_y.set,
            xscrollcommand=scroll_remote_x.set
        )
        
        self.remote_tree.grid(row=1, column=0, sticky="nsew")
        scroll_remote_y.grid(row=1, column=1, sticky="ns")
        scroll_remote_x.grid(row=2, column=0, sticky="ew")
        
        # Bind double-click event for remote tree
        self.remote_tree.bind("<Double-1>", self.on_remote_double_click)
        
        # Remote file buttons
        remote_btn_frame = tk.Frame(remote_frame, bg=BG_COLOR)
        remote_btn_frame.grid(row=3, column=0, sticky="ew", pady=(5, 0))
        
        download_btn = tk.Button(
            remote_btn_frame, 
            text="Download", 
            command=self.download_file,
            width=10,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        download_btn.pack(side="left", padx=2)
        
        delete_remote_btn = tk.Button(
            remote_btn_frame, 
            text="Delete", 
            command=self.delete_remote_file,
            width=10,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        delete_remote_btn.pack(side="left", padx=2)
        
        mkdir_btn = tk.Button(
            remote_btn_frame, 
            text="New Folder", 
            command=self.create_remote_folder,
            width=10,
            bg=BUTTON_COLOR,
            activebackground=ACTIVE_COLOR,
            relief=tk.GROOVE
        )
        mkdir_btn.pack(side="left", padx=2)
        
        # Status/log area
        log_frame = tk.LabelFrame(
            self.root, 
            text="Activity Log", 
            bg=BG_COLOR, 
            padx=5, 
            pady=5
        )
        log_frame.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame, 
            width=100, 
            height=8,
            wrap=tk.WORD,
            bg="white",
            fg=TEXT_COLOR
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")
        
        # Initialize file lists
        self.update_local_file_list()
        
    def on_local_double_click(self, event):
        """Handle double-click on local files"""
        selected = self.local_tree.selection()
        if not selected:
            return
            
        item = self.local_tree.item(selected[0])
        filename = item['values'][0]
        
        # Handle parent directory navigation
        if filename == "..":
            current_path = self.local_path_var.get()
            parent_dir = os.path.dirname(current_path)
            if parent_dir != current_path:  # Not root directory
                self.local_path_var.set(parent_dir)
                self.update_local_file_list()
            return
            
        # Handle directory navigation
        local_path = os.path.join(self.local_path_var.get(), filename)
        if os.path.isdir(local_path):
            self.local_path_var.set(local_path)
            self.update_local_file_list()
            
    def on_remote_double_click(self, event):
        """Handle double-click on remote files"""
        if not self.ftp:
            return
            
        selected = self.remote_tree.selection()
        if not selected:
            return
            
        item = self.remote_tree.item(selected[0])
        filename = item['values'][0]
        
        # Handle parent directory navigation
        if filename == "..":
            current_path = self.ftp.pwd()
            if current_path != "/":
                self.ftp.cwd("..")
                self.refresh_remote()
            return
            
        # Handle directory navigation
        if item['values'][1] == "DIR":
            try:
                self.ftp.cwd(filename)
                self.refresh_remote()
            except Exception as e:
                self.log_message(f"❌ Error changing directory: {e}")
        
    def log_message(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.configure(state="disabled")
        self.log_text.see(tk.END)
        
    def check_rsa_keys(self):
        try:
            if not (os.path.exists("private.pem") and os.path.exists("public.pem")):
                self.log_message("🔐 Generating RSA key pair...")
                key = RSA.generate(2048)
                with open("private.pem", "wb") as f:
                    f.write(key.export_key())
                with open("public.pem", "wb") as f:
                    f.write(key.publickey().export_key())
                self.log_message("✅ RSA key pair generated.")
        except Exception as e:
            self.log_message(f"❌ Error generating RSA keys: {e}")
            
    def scan_network(self):
        def scan_thread():
            try:
                self.log_message("🔍 Scanning network for FTP servers...")
                subnet = "192.168.66.0/24"
                active_hosts = self.sweep_for_ftp_servers(subnet)
                
                self.server_combobox['values'] = active_hosts
                if active_hosts:
                    self.server_var.set(active_hosts[0])
                    self.log_message(f"✅ Found {len(active_hosts)} FTP server(s)")
                else:
                    self.log_message("❌ No FTP servers found on the local network.")
            except Exception as e:
                self.log_message(f"❌ Network scan failed: {e}")
                
        threading.Thread(target=scan_thread, daemon=True).start()
        
    def connect_to_server(self):
        server_ip = self.server_var.get().strip()
        if not server_ip:
            messagebox.showerror("Error", "Please select or enter a server IP")
            return
            
        def connect_thread():
            try:
                self.log_message(f"🌐 Connecting to {server_ip}...")
                self.ftp = FTP()
                self.ftp.connect(server_ip, FTP_PORT)
                self.ftp.login(FTP_USER, FTP_PASS)
                self.server_ip = server_ip
                self.connection_label.config(text=f"Connected to {server_ip}", fg="#ddffdd")
                self.log_message(f"✅ Connected to FTP Server at {server_ip}")
                self.refresh_remote()
            except Exception as e:
                self.log_message(f"❌ Connection failed: {e}")
                messagebox.showerror("Connection Error", str(e))
                
        threading.Thread(target=connect_thread, daemon=True).start()
        
    def disconnect_from_server(self):
        if self.ftp:
            try:
                self.ftp.quit()
                self.log_message("👋 Disconnected from server")
                self.connection_label.config(text="Not Connected", fg="#ffdddd")
            except Exception as e:
                self.log_message(f"❌ Error disconnecting: {e}")
            finally:
                self.ftp = None
                self.remote_tree.delete(*self.remote_tree.get_children())
                
    def browse_local(self):
        """Open system file browser to select files"""
        try:
            # This will open the native file browser in file selection mode
            filepaths = filedialog.askopenfilenames(
                title="Select Files",
                initialdir=self.local_path_var.get()
            )
            
            if filepaths:
                # Update to the directory containing the first selected file
                first_file_dir = os.path.dirname(filepaths[0])
                self.local_path_var.set(first_file_dir)
                self.update_local_file_list()
                
                # Highlight the selected files in the treeview
                for filepath in filepaths:
                    filename = os.path.basename(filepath)
                    for child in self.local_tree.get_children():
                        if self.local_tree.item(child)['values'][0] == filename:
                            self.local_tree.selection_set(child)
                            break
                
        except Exception as e:
            self.log_message(f"❌ Error browsing files: {e}")

    def upload_file(self):
        """Upload currently selected files"""
        if not self.ftp:
            messagebox.showerror("Error", "Not connected to a server")
            return
            
        selected = self.local_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select files to upload (use Browse button)")
            return
            
        for item_id in selected:
            item = self.local_tree.item(item_id)
            filename = item['values'][0]
            
            if filename == "..":
                continue
                
            local_path = os.path.join(self.local_path_var.get(), filename)
            if os.path.isdir(local_path):
                continue
                
            def do_upload(filepath):
                try:
                    encrypted_path = f"{filepath}.enc"
                    self.encrypt_file(filepath, encrypted_path)
                    
                    remote_filename = os.path.basename(encrypted_path)
                    with open(encrypted_path, "rb") as f:
                        self.ftp.storbinary(f"STOR {remote_filename}", f)
                        
                    os.remove(encrypted_path)
                    self.log_message(f"✅ Uploaded: {os.path.basename(filepath)}")
                    
                except Exception as e:
                    self.log_message(f"❌ Failed to upload {os.path.basename(filepath)}: {e}")
            
            # Start upload in a new thread
            threading.Thread(target=do_upload, args=(local_path,), daemon=True).start()
        
        self.refresh_remote()
            
        def upload_thread():
            try:
                encrypted_path = f"{local_path}.enc"
                self.encrypt_file(local_path, encrypted_path)
                
                remote_filename = os.path.basename(encrypted_path)
                with open(encrypted_path, "rb") as f:
                    self.ftp.storbinary(f"STOR {remote_filename}", f)
                    
                os.remove(encrypted_path)
                self.log_message(f"✅ Uploaded and encrypted: {filename} ➜ {remote_filename}")
                self.refresh_remote()
            except Exception as e:
                self.log_message(f"❌ Upload failed: {e}")
                
        threading.Thread(target=upload_thread, daemon=True).start()
            
    def update_local_file_list(self):
        path = self.local_path_var.get()
        if not os.path.isdir(path):
            return
            
        self.local_tree.delete(*self.local_tree.get_children())
        
        try:
            # Add parent directory entry
            parent_dir = os.path.dirname(path)
            if parent_dir != path:  # Not root directory
                self.local_tree.insert("", "end", values=("..", "DIR"), tags=("dir",))
            
            # List all files and directories
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                if os.path.isdir(full_path):
                    self.local_tree.insert("", "end", values=(item, "DIR"), tags=("dir",))
                else:
                    size = os.path.getsize(full_path)
                    size_str = self.format_size(size)
                    self.local_tree.insert("", "end", values=(item, size_str), tags=("file",))
                    
            # Configure tags for styling
            self.local_tree.tag_configure("dir", foreground="blue")
            self.local_tree.tag_configure("file", foreground="black")
            
        except Exception as e:
            self.log_message(f"❌ Error listing local files: {e}")
            
    def format_size(self, size):
        try:
            # Convert size to human-readable format
            for unit in ['B', 'KB', 'MB', 'GB']:
                if size < 1024.0:
                    return f"{size:.1f} {unit}"
                size /= 1024.0
            return f"{size:.1f} TB"
        except Exception as e:
            self.log_message(f"❌ Error formatting size: {e}")
            return "N/A"
        
    def refresh_remote(self):
        if not self.ftp:
            messagebox.showerror("Error", "Not connected to a server")
            return
            
        def refresh_thread():
            try:
                self.remote_tree.delete(*self.remote_tree.get_children())
                current_path = self.ftp.pwd()
                self.remote_path_var.set(current_path)
                
                # Add parent directory entry if not root
                if current_path != "/":
                    self.remote_tree.insert("", "end", values=("..", "DIR"), tags=("dir",))
                
                # List remote files
                files = []
                self.ftp.retrlines("LIST", files.append)
                
                for line in files:
                    parts = line.split()
                    if len(parts) < 9:
                        continue
                        
                    # Parse FTP LIST output
                    name = " ".join(parts[8:])
                    if parts[0].startswith("d"):
                        self.remote_tree.insert("", "end", values=(name, "DIR"), tags=("dir",))
                    else:
                        size = parts[4]
                        size_str = self.format_size(int(size)) if size.isdigit() else size
                        self.remote_tree.insert("", "end", values=(name, size_str), tags=("file",))
                
                # Configure tags for styling
                self.remote_tree.tag_configure("dir", foreground="blue")
                self.remote_tree.tag_configure("file", foreground="black")
                
            except Exception as e:
                self.log_message(f"❌ Error listing remote files: {e}")
                
        threading.Thread(target=refresh_thread, daemon=True).start()
        
    def download_file(self):
        if not self.ftp:
            messagebox.showerror("Error", "Not connected to a server")
            return
            
        # Get selected remote file
        selected = self.remote_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a file to download")
            return
            
        item = self.remote_tree.item(selected[0])
        filename = item['values'][0]
        
        # Handle parent directory navigation
        if filename == "..":
            return
            
        if item['values'][1] == "DIR":
            messagebox.showinfo("Info", "Please select a file, not a directory")
            return
            
        # Check if filename ends with .enc (should be encrypted)
        if not filename.endswith(".enc"):
            messagebox.showwarning("Warning", "This file doesn't appear to be encrypted (.enc extension missing)")
            
        def download_thread():
            try:
                # Create downloads directory if it doesn't exist
                downloads_dir = os.path.join(os.getcwd(), "downloads")
                os.makedirs(downloads_dir, exist_ok=True)
                
                # Download the encrypted file
                encrypted_path = os.path.join(downloads_dir, filename)
                with open(encrypted_path, "wb") as f:
                    self.ftp.retrbinary(f"RETR {filename}", f.write)
                    
                # Decrypt the file
                decrypted_path = encrypted_path[:-4]  # Remove .enc extension
                self.decrypt_file(encrypted_path, decrypted_path)
                
                self.log_message(f"✅ Downloaded and decrypted: {filename} ➜ {os.path.basename(decrypted_path)}")
                self.update_local_file_list()
            except Exception as e:
                self.log_message(f"❌ Download failed: {e}")
                
        threading.Thread(target=download_thread, daemon=True).start()
        
    def delete_remote_file(self):
        if not self.ftp:
            messagebox.showerror("Error", "Not connected to a server")
            return
            
        # Get selected remote file
        selected = self.remote_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Please select a file to delete")
            return
            
        item = self.remote_tree.item(selected[0])
        filename = item['values'][0]
        
        # Handle parent directory navigation
        if filename == "..":
            return
            
        # Confirm deletion
        if not messagebox.askyesno("Confirm", f"Delete {filename} from server?"):
            return
            
        def delete_thread():
            try:
                if item['values'][1] == "DIR":
                    self.ftp.rmd(filename)
                else:
                    self.ftp.delete(filename)
                    
                self.log_message(f"🗑️ Deleted: {filename}")
                self.refresh_remote()
            except Exception as e:
                self.log_message(f"❌ Delete failed: {e}")
                
        threading.Thread(target=delete_thread, daemon=True).start()
        
    def create_remote_folder(self):
        if not self.ftp:
            messagebox.showerror("Error", "Not connected to a server")
            return
            
        folder_name = simpledialog.askstring("New Folder", "Enter folder name:")
        if not folder_name:
            return
            
        def create_thread():
            try:
                self.ftp.mkd(folder_name)
                self.log_message(f"📂 Created folder: {folder_name}")
                self.refresh_remote()
            except Exception as e:
                self.log_message(f"❌ Create folder failed: {e}")
                
        threading.Thread(target=create_thread, daemon=True).start()
        
    def encrypt_file(self, input_file, output_file, pub_key_path="public.pem"):
        try:
            with open(pub_key_path, "rb") as f:
                pub_key = RSA.import_key(f.read())
            cipher = PKCS1_OAEP.new(pub_key)
            with open(input_file, "rb") as f:
                data = f.read()
            chunk_size = 190
            encrypted_data = b"".join(
                cipher.encrypt(data[i:i+chunk_size]) 
                for i in range(0, len(data), chunk_size))
            with open(output_file, "wb") as f:
                f.write(encrypted_data)
        except Exception as e:
            self.log_message(f"❌ Encryption failed: {e}")
            raise
            
    def decrypt_file(self, input_file, output_file, priv_key_path="private.pem"):
        try:
            with open(priv_key_path, "rb") as f:
                priv_key = RSA.import_key(f.read())
            cipher = PKCS1_OAEP.new(priv_key)
            with open(input_file, "rb") as f:
                encrypted_data = f.read()
            chunk_size = 256
            decrypted_data = b"".join(
                cipher.decrypt(encrypted_data[i:i+chunk_size]) 
                for i in range(0, len(encrypted_data), chunk_size))
            with open(output_file, "wb") as f:
                f.write(decrypted_data)
        except Exception as e:
            self.log_message(f"❌ Decryption failed: {e}")
            raise

    def sweep_for_ftp_servers(self, subnet="192.168.66.0/24", port=FTP_PORT, max_threads=50):
        active_hosts = []
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = [executor.submit(self.check_ftp_host, ip, port) for ip in ipaddress.IPv4Network(subnet)]
            for future in futures:
                result = future.result()
                if result:
                    active_hosts.append(result)
        return active_hosts

    def check_ftp_host(self, ip, port=FTP_PORT, timeout=1):
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                return str(ip)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return None

# === Main Application ===
if __name__ == "__main__":
    root = tk.Tk()
    app = FTPClientGUI(root)
    
    # Configure styles
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background="white", fieldbackground="white")
    style.configure("Treeview.Heading", background=BUTTON_COLOR)
    
    root.mainloop()
import os
from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer

def run_ftp_server():
    # Step 1: Set target FTP folder and ensure it exists
    ftp_root = os.path.abspath("Folder")  # single capital F — match exactly!
    os.makedirs(ftp_root, exist_ok=True)
    print(f"[DEBUG] FTP Root set to: {ftp_root}")
    print("helllo")

    # Step 2: Create an FTP user with full access to that folder
    authorizer = DummyAuthorizer()
    authorizer.add_user("user", "12345", ftp_root, perm="elradfmwMT")  # root path is now correct

    # Step 3: Assign authorizer to handler
    handler = FTPHandler
    handler.authorizer = authorizer
    handler.abstracted_fs.root = ftp_root  # This line helps reinforce the root path

    # Step 4: Start server
    server = FTPServer(("0.0.0.0", 2121), handler)
    print(f"FTP server started. Files will be stored in: {ftp_root}")
    server.serve_forever()

if __name__ == "__main__":
    run_ftp_server()

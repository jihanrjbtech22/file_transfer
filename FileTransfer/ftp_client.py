from pyftpdlib.servers import FTPServer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer

def run_ftp_server():
    authorizer = DummyAuthorizer()
    # Create a user with full permissions
    authorizer.add_user("user", "12345", ".", perm="elradfmwMT")  # '.' means current directory

    handler = FTPHandler
    handler.authorizer = authorizer

    server = FTPServer(("0.0.0.0", 2121), handler)
    print("Starting FTP server on port 2121...")
    server.serve_forever()

if __name__ == "__main__":
    run_ftp_server()

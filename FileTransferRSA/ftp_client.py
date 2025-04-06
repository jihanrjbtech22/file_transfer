from ftplib import FTP

def upload_file(Rx_IP, filename):
    ftp = FTP()
    ftp.connect(Rx_IP, 2121)
    ftp.login("user", "12345")

    #filename = "abc.txt"
    with open(filename, "rb") as f:
        ftp.storbinary(f"STOR {filename}", f)
    print(f"Uploaded {filename} successfully.")

    ftp.quit()

def download_file(Rx_IP, filename):
    ftp = FTP()
    ftp.connect(Rx_IP, 2121)
    ftp.login("user", "12345")

    #filename = "defg.txt"
    with open(filename, "wb") as f:
        ftp.retrbinary(f"RETR {filename}", f.write)
    print(f"Downloaded {filename} successfully.")

    ftp.quit()

def list_files_on_ftp(Rx_IP):
    ftp = FTP()
    ftp.connect(Rx_IP, 2121)  # Replace with the actual Linux machine IP
    ftp.login("user", "12345")

    print("Contents of 'Folder' on FTP server:")
    ftp.retrlines("LIST")  # This lists files/folders in the current directory

    ftp.quit()

# Choose to upload or download or list
upload_file("192.168.65.6","../Files/.txt")
# download_file("192.168.65.6","abc.txt")
#list_files_on_ftp("192.168.65.6")

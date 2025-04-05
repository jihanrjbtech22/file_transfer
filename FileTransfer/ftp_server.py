from ftplib import FTP

def upload_file():
    ftp = FTP()
    ftp.connect("LINUX_IP_HERE", 2121)
    ftp.login("user", "12345")

    filename = "test_upload.txt"
    with open(filename, "rb") as f:
        ftp.storbinary(f"STOR {filename}", f)
    print(f"Uploaded {filename} successfully.")

    ftp.quit()

def download_file():
    ftp = FTP()
    ftp.connect("LINUX_IP_HERE", 2121)
    ftp.login("user", "12345")

    filename = "test_download.txt"
    with open(filename, "wb") as f:
        ftp.retrbinary(f"RETR {filename}", f.write)
    print(f"Downloaded {filename} successfully.")

    ftp.quit()

# Choose to upload or download
upload_file()
# download_file()

import os
import sys
import subprocess

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    print("=" * 50)
    print("🔐 RSA Secure File Transfer System")
    print("=" * 50)

def show_menu():
    print("\nChoose a mode to run:")
    print("1. Run as Server")
    print("2. Run as Client")
    print("3. Exit")

def run_server():
    server_path = os.path.join("Server", "ftp_server.py")
    if not os.path.exists(server_path):
        print("❌ Server script not found.")
        return
    print("🚀 Starting Server...\n")
    subprocess.run([sys.executable, server_path])

def run_client():
    client_path = os.path.join("Client", "ftp_client_shell.py")
    if not os.path.exists(client_path):
        print("❌ Client script not found.")
        return
    print("🖥️  Starting Client Shell...\n")
    subprocess.run([sys.executable, client_path])

def main():
    while True:
        clear_screen()
        banner()
        show_menu()

        choice = input("\nEnter your choice (1/2/3): ").strip()
        if choice == '1':
            run_server()
        elif choice == '2':
            run_client()
        elif choice == '3':
            print("👋 Exiting...")
            break
        else:
            print("❌ Invalid choice. Try again.")
            input("Press Enter to continue...")

if __name__ == "__main__":
    main()

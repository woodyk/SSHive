#!/usr/bin/env python3
#
# sshive.py

#!/usr/bin/env python3

import socket
import paramiko
import threading
import logging
import argparse
import os
import sys
import signal
from paramiko import SSHException

# Constants
DEFAULT_PORT = 2222
DEFAULT_KEY_PATH = "/tmp/ssh_honeypot_rsa"
DEFAULT_LOG_FILE = "ssh_honeypot.log"
PID_FILE = "/tmp/ssh_honeypot.pid"
HOST = "0.0.0.0"  # Listen on all network interfaces
SSH_BANNER = "SSH-2.0-OpenSSH_5.3" # Default to old known exploitable version

# Argument parsing
parser = argparse.ArgumentParser(description="SSH Honeypot Server")
parser.add_argument("-d", "--daemon", action="store_true", help="Run in daemon mode (background)")
parser.add_argument("-l", "--log", type=str, default=DEFAULT_LOG_FILE, help="Specify log file (default: ssh_honeypot.log)")
parser.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Specify port to listen on (default: 2222)")
parser.add_argument("--ps", action="store_true", help="Check if the honeypot is running")
parser.add_argument("--stop", action="store_true", help="Stop a running honeypot daemon")
args = parser.parse_args()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# Create a file handler for logging to a file
file_handler = logging.FileHandler(args.log)
file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
logging.getLogger().addHandler(file_handler)

# If running in foreground, also log to stdout
if not args.daemon:
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logging.getLogger().addHandler(stream_handler)

# Generate or load host key
if os.path.exists(DEFAULT_KEY_PATH):
    host_key = paramiko.RSAKey(filename=DEFAULT_KEY_PATH)
else:
    host_key = paramiko.RSAKey.generate(2048)
    host_key.write_private_key_file(DEFAULT_KEY_PATH)
    logging.info(f"Generated new host key at {DEFAULT_KEY_PATH}")

def write_pid_file():
    """Writes the PID file."""
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))
    logging.info(f"PID file created at {PID_FILE}")

def remove_pid_file():
    """Removes the PID file."""
    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
        logging.info(f"PID file {PID_FILE} removed")

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, client_address):
        self.client_address = client_address
        super().__init__()

    def check_auth_password(self, username, password):
        """
        Intercepts login attempts with username and password.
        Logs the attempt and denies authentication.
        """
        logging.info(f"Attempted login - IP: {self.client_address[0]}, Username: {username}, Password: {password}")
        return paramiko.AUTH_FAILED  # Always deny authentication

    def get_allowed_auths(self, username):
        return "password"  # Only allow password authentication for simplicity

def handle_client(client_socket, client_address):
    """
    Handles incoming client connection and sets up SSH transport.
    """
    try:
        # Set up the SSH transport layer
        transport = paramiko.Transport(client_socket)
        transport.local_version = SSH_BANNER  # Set the SSH banner
        transport.add_server_key(host_key)

        # Instantiate our custom SSH server class
        server = SSHHoneypot(client_address)

        try:
            # Start the server and listen for authentication attempts
            transport.start_server(server=server)
        except paramiko.SSHException as e:
            logging.warning(f"SSH protocol error with {client_address[0]}: {e}")
            return
        except EOFError:
            logging.warning(f"Client {client_address[0]} disconnected unexpectedly during SSH banner exchange.")
            return

        # Keep the connection open to simulate a real SSH server
        while True:
            channel = transport.accept(20)  # Wait up to 20 seconds for a connection
            if channel is None:
                break
            channel.close()
    
    except EOFError:
        logging.warning(f"Client {client_address[0]} disconnected unexpectedly during SSH banner exchange.")
    except paramiko.SSHException as e:
        logging.warning(f"SSH protocol error with {client_address[0]}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error with client {client_address[0]}: {e}")
    
    finally:
        client_socket.close()

def start_honeypot():
    """Starts the honeypot server, listening for incoming SSH connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, args.port))
    server_socket.listen(100)
    logging.info(f"SSH honeypot started on port {args.port}")
    write_pid_file()  # Write the PID file

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            logging.info(f"Connection attempt from {client_address[0]}")
            client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
            client_handler.start()
    finally:
        remove_pid_file()  # Clean up PID file on exit

def daemonize():
    """Daemonize the process by detaching from the terminal and running in the background."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)

    sys.stdout.flush()
    sys.stderr.flush()

    with open("/dev/null", "r") as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    with open("/dev/null", "a") as devnull:
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

def check_honeypot_running():
    """Checks if the honeypot is running by reading the PID file."""
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, 0)  # Check if process is running
            print(f"Honeypot is running with PID {pid}")
            return True
        except ProcessLookupError:
            print("PID file exists but no process found. Removing stale PID file.")
            remove_pid_file()
    print("Honeypot is not running.")
    return False

def stop_honeypot():
    """Stops the honeypot by killing the process based on the PID file."""
    if os.path.exists(PID_FILE):
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"Honeypot process with PID {pid} stopped.")
            remove_pid_file()
        except ProcessLookupError:
            print("No such process found. Removing stale PID file.")
            remove_pid_file()
    else:
        print("Honeypot is not running.")

if __name__ == "__main__":
    if args.ps:
        check_honeypot_running()
    elif args.stop:
        stop_honeypot()
    else:
        if args.daemon:
            daemonize()
        start_honeypot()

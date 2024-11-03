# SSHive - An SSH Honeypot

SSHive is a simple yet effective SSH honeypot designed to monitor, log, and analyze unauthorized SSH access attempts. 
It acts as a trap for potential attackers, capturing details such as IP addresses, attempted usernames, passwords, 
and connection details. SSHive runs as a daemon or in the foreground, providing detailed logs for security monitoring.

## Features

- **SSH Banner Simulation**: Mimics a real SSH server banner to attract attackers.
- **Connection Logging**: Captures and logs source IP, attempted username, and password.
- **Daemon Mode**: Runs in the background with a PID file for easy management.
- **Customizable Logging**: Logs to a specified file with an option for console output in foreground mode.
- **PID Tracking**: Provides status and stop functionality for daemonized processes.
- **Automatic Key Management**: Generates and stores RSA host keys if not found.

## Installation

1. **Install Python Dependencies**

   SSHive requires the `paramiko` library for SSH functionality. Install dependencies using pip:

   ```bash
   pip install paramiko
   ```

2. **Clone the Repository**

   Clone this repository and navigate to the project directory:

   ```bash
   git clone https://github.com/woodyk/SSHive.git
   cd SSHive
   ```

## Usage

Run SSHive with different command-line options as needed:

- **Run in Foreground (default)**:

  ```bash
  python3 sshive.py
  ```

- **Run in Daemon Mode**:

  ```bash
  python3 sshive.py -d
  ```

- **Specify Custom Log File**:

  ```bash
  python3 sshive.py -l /path/to/logfile.log
  ```

- **Check if SSHive is Running**:

  ```bash
  python3 sshive.py --ps
  ```

- **Stop the Daemonized SSHive**:

  ```bash
  python3 sshive.py --stop
  ```

## Command-Line Options

| Option         | Description                                     |
|----------------|-------------------------------------------------|
| `-d`, `--daemon` | Run SSHive in the background as a daemon.       |
| `-l`, `--log`   | Specify a custom log file for logging.          |
| `-p`, `--port`  | Specify a custom port to listen on (default: 2222). |
| `--ps`          | Check if SSHive is currently running.           |
| `--stop`        | Stop the running SSHive daemon.                 |

## Log Details

SSHive logs connection attempts with the following information:
- Timestamp of the attempt
- Source IP address
- Attempted username
- Password used

Logs are saved in the specified log file or `ssh_honeypot.log` by default.

## Security Notes

- **Sensitive Data**: SSHive logs usernames and passwords in plain text for security monitoring. Ensure the log file is protected.
- **Use Responsibly**: SSHive is a tool for monitoring unauthorized access attempts and should be used responsibly. Always adhere to local regulations and privacy policies.

## License

SSHive is released under the MIT License.

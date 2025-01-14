# Raspberry Pi Controller Web Application

This project is a Flask-based web application designed to control and monitor a Raspberry Pi. It provides functionalities such as GPIO control, Wi-Fi and Bluetooth management, system monitoring, and remote command execution via SSH.

## Features

- **GPIO Control**: Toggle GPIO pins on and off.
- **Wi-Fi Management**: Scan and connect to Wi-Fi networks.
- **Bluetooth Management**: Scan and connect to Bluetooth devices.
- **System Monitoring**: Monitor CPU, RAM, GPU, disk, and network usage.
- **Remote Command Execution**: Execute commands on the Raspberry Pi via SSH.
- **User  Authentication**: Login and registration system with password hashing.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/AnubisSK/RasperryControll.git
   cd RasperryControll

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt

3. **Set Up the Database**:
   ```bash
   python
   >>> from app import db
   >>> db.create_all()

4. **Run the Application**:
   ```bash
   python app.py

4. **Access the Application**:
   Open your web browser and navigate to http://localhost:5000.

Usage
GPIO Control
Endpoint: /gpio/toggle/<int:pin>
Method: POST
Body: {"state": true} or {"state": false}
Description: Toggles the state of the specified GPIO pin.
Wi-Fi Management
Scan Wi-Fi Networks:

Endpoint: /scan_wifi
Method: GET
Description: Scans for available Wi-Fi networks.
Connect to Wi-Fi:

Endpoint: /connect_wifi
Method: POST
Body: {"ssid": "your_ssid", "password": "your_password"}
Description: Connects to the specified Wi-Fi network.
Bluetooth Management
Scan Bluetooth Devices:

Endpoint: /scan_bluetooth
Method: GET
Description: Scans for available Bluetooth devices.
Connect to Bluetooth Device:

Endpoint: /connect_bluetooth
Method: POST
Body: {"mac_address": "your_mac_address"}
Description: Connects to the specified Bluetooth device.
System Monitoring
CPU Usage:

Endpoint: /cpu_usage
Method: GET
Description: Returns the current CPU usage.
RAM Usage:

Endpoint: /ram_usage
Method: GET
Description: Returns the current RAM usage.
GPU Usage:

Endpoint: /gpu_usage
Method: GET
Description: Returns the current GPU usage.
Disk Usage:

Endpoint: /disk_usage
Method: GET
Description: Returns the current disk usage.
Network Usage:

Endpoint: /network_usage
Method: GET
Description: Returns the current network usage.
Remote Command Execution
Execute Command:
Endpoint: /execute
Method: POST
Body: {"command": "your_command"}
Description: Executes the specified command on the Raspberry Pi via SSH.
User Authentication
Login:

Endpoint: /login
Method: POST
Body: {"username": "your_username", "password": "your_password"}
Description: Logs in the user.
Register:

Endpoint: /register
Method: POST
Body: {"username": "your_username", "email": "your_email", "password": "your_password"}
Description: Registers a new user.
Logout:

Endpoint: /logout
Method: GET
Description: Logs out the user.
Wi-Fi Access Point Setup
Setup Wi-Fi AP:
Endpoint: /setup_wifi_ap
Method: POST
Description: Configures the Raspberry Pi as a Wi-Fi access point. 

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

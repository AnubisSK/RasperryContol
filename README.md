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

## Configuration
- **Secret Key**:: Set a strong secret key in app.secret_key.
- **Database**: Configure the database URI in app.config['SQLALCHEMY_DATABASE_URI'].
- **SSH Connection**: Set the SSH host, port, username, and password in the respective variables.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request.

## License
This project is licensed under the MIT License.


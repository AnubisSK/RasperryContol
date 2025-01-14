from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import psutil
import GPUtil
import socket
import logging
import paramiko
import RPi.GPIO as GPIO
import subprocess


app = Flask(__name__)
app.secret_key = 'xz1DTq*Vmu9>e6:472t,TM#3=tmusri-Lk@,57ZoYq`en1g)|qmO-WAZqr]:ikV'  # Nastav si silný tajný kľúč pre session

def scan_wifi():
    """Funkcia na skenovanie dostupných Wi-Fi sietí."""
    try:
        result = subprocess.run(['nmcli', '-f', 'SSID,SECURITY,SIGNAL', 'dev', 'wifi'], capture_output=True, text=True)
        if result.returncode == 0:
            wifi_networks = []
            lines = result.stdout.splitlines()[1:]  # Preskočíme hlavičku
            for line in lines:
                parts = line.split()
                ssid = parts[0]
                security = parts[1] if len(parts) > 1 else "Open"
                signal = parts[2] if len(parts) > 2 else "0%"
                wifi_networks.append({
                    'ssid': ssid,
                    'security': security,
                    'signal': signal
                })
            return wifi_networks
        else:
            return {"error": "Nepodarilo sa skenovať Wi-Fi siete."}
    except Exception as e:
        return {"error": f"Chyba pri skenovaní Wi-Fi sietí: {str(e)}"}

def scan_bluetooth():
    """Funkcia na skenovanie dostupných Bluetooth zariadení."""
    try:
        subprocess.run(['bluetoothctl', 'scan', 'on'], capture_output=True, text=True, timeout=10)
        result = subprocess.run(['bluetoothctl', 'devices'], capture_output=True, text=True)
        if result.returncode == 0:
            bluetooth_devices = []
            lines = result.stdout.splitlines()
            for line in lines:
                parts = line.split(maxsplit=2)
                if len(parts) >= 2:
                    mac_address = parts[1]
                    name = parts[2] if len(parts) > 2 else "Unknown"
                    bluetooth_devices.append({
                        'mac_address': mac_address,
                        'name': name
                    })
            return bluetooth_devices
        else:
            return {"error": "Nepodarilo sa skenovať Bluetooth zariadenia."}
    except Exception as e:
        return {"error": f"Chyba pri skenovaní Bluetooth zariadení: {str(e)}"}

def connect_to_wifi(ssid, password):
    """Funkcia na pripojenie k Wi-Fi sieti."""
    try:
        result = subprocess.run(['nmcli', 'dev', 'wifi', 'connect', ssid, 'password', password], capture_output=True, text=True)
        if result.returncode == 0:
            return {"message": f"Úspešne pripojené k {ssid}."}
        else:
            return {"error": f"Nepodarilo sa pripojiť k {ssid}."}
    except Exception as e:
        return {"error": f"Chyba pri pripájaní k Wi-Fi sieti: {str(e)}"}

def connect_to_bluetooth(mac_address):
    """Funkcia na pripojenie k Bluetooth zariadeniu."""
    try:
        result = subprocess.run(['bluetoothctl', 'connect', mac_address], capture_output=True, text=True)
        if result.returncode == 0:
            return {"message": f"Úspešne pripojené k {mac_address}."}
        else:
            return {"error": f"Nepodarilo sa pripojiť k {mac_address}."}
    except Exception as e:
        return {"error": f"Chyba pri pripájaní k Bluetooth zariadeniu: {str(e)}"}

# Nastavenie režimu pinu
GPIO.setmode(GPIO.BCM)
GPIO.setwarnings(False)

# Inicializácia GPIO pinov
for pin in range(1, 41):
    GPIO.setup(pin, GPIO.OUT)

# Funkcia pre zistenie aktívneho pinu
def get_active_pin():
    for pin in range(2, 27):
        if GPIO.input(pin):
            return pin
    return None

@app.route('/gpio/toggle/<int:pin>', methods=['POST'])
def toggle_gpio(pin):
    """Funkcia na prepínanie stavu GPIO pinu."""
    state = request.json.get('state')
    if pin < 1 or pin > 40:
        return jsonify({"success": False, "error": "Neplatný pin."}), 400

    GPIO.output(pin, GPIO.HIGH if state else GPIO.LOW)
    return jsonify({"success": True})

# Funkcia pre togglePin
def togglePin(pin):
    GPIO.setup(pin, GPIO.OUT)
    GPIO.output(pin, not GPIO.input(pin))

def setup_wifi_ap():
    try:
        # Zastavenie služieb, ak sú spustené
        subprocess.run(['sudo', 'systemctl', 'stop', 'hostapd'], check=True)
        subprocess.run(['sudo', 'systemctl', 'stop', 'dnsmasq'], check=True)

        # Nastavenie hostapd.con
        hostapd_config = '''
interface=wlan0
driver=nl80211
ssid=WIFI_RASPI_CONTROLL
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=your_secure_password
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
'''
        with open('/etc/hostapd/hostapd.conf', 'w') as f:
             f.write(hostapd_config)

        # Nastavenie dnsmasq.conf
        dnsmasq_config = '''
interface=wlan0
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
'''
        with open('/etc/dnsmasq.conf', 'w') as f:
            f.write(dnsmasq_config)

        # Nastavenie statickej IP adresy pre wlan0
        dhcpcd_config = '''
interface wlan0
static ip_address=192.168.4.1/24
nohook wpa_supplicant
'''
        with open('/etc/dhcpcd.conf', 'a') as f:
            f.write(dhcpcd_config)

        # Spustenie služieb
        subprocess.run(['sudo', 'systemctl', 'unmask', 'hostapd'], check=True)
        subprocess.run(['sudo', 'systemctl', 'enable', 'hostapd'], check=True)
        subprocess.run(['sudo', 'systemctl', 'start', 'hostapd'], check=True)
        subprocess.run(['sudo', 'systemctl', 'enable', 'dnsmasq'], check=True)
        subprocess.run(['sudo', 'systemctl', 'start', 'dnsmasq'], check=True)

        return "Wi-Fi AP nastavený úspešne."
    except subprocess.CalledProcessError as e:
        return f"Nastala chyba pri spúšťaní príkazov: {str(e)}"
    except Exception as e:
        return f"Nastala chyba: {str(e)}"

# Endpoint pre nastavenie Wi-Fi AP
@app.route('/setup_wifi_ap', methods=['POST'])
def setup_wifi_ap_endpoint():
    result = setup_wifi_ap()
    return jsonify({'message': result})

# Endpoint pre togglePin
@app.route('/togglePin', methods=['GET'])
def togglePinEndpoint():
    active_pin = get_active_pin()
    if active_pin:
        togglePin(active_pin)
        return jsonify({'message': f'Pin {active_pin} toggled'})
    else:
        return jsonify({'message': 'No active pin found'})


# Nastavenie SSH pripojenia
ssh_host = 'rasperrypi.local'
ssh_port = 22
ssh_username = 'root'
ssh_password = 'Password'

# Vytvorenie SSH klienta
ssh_client = paramiko.SSHClient()
ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Pripojenie cez SSH
ssh_client.connect(hostname=ssh_host, port=ssh_port, username=ssh_username, password=ssh_password)

# Vytvorenie terminálu
stdin, stdout, stderr = ssh_client.exec_command('bash')

# Funkcia pre vykonanie prikazu
def execute_command(command):
    stdin.write(command + '\n')
    stdin.flush()
    output = stdout.read().decode('utf-8')
    return output

@app.route('/execute', methods=['POST'])
def execute():
    command = request.form['command']
    output = execute_command(command)
    return output

# Nastavenie logovania
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# Nastavenia pre zapnutie/vypnutie funkcionalít
app.config['LOGIN_ENABLED'] = True
app.config['REGISTER_ENABLED'] = False

# Konfigurácia databázy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'  # SQLite databáza
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Inicializácia SQLAlchemy
db = SQLAlchemy(app)

# Model používateľa
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

    def __repr__(self):
        return f"User ('{self.username}', '{self.email}')"

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/gpio_ovladanie')
def gpio_ovladanie():
    if 'username' in session:
        return render_template('gpio-ovladanie.html', username=session['username'])
    else:
        flash('Prosím, prihláste sa najprv.', 'warning')
        return redirect(url_for('login'))


@app.route('/konzoĺa')
def konzola():
    if 'username' in session:
        return render_template('konzola.html', username=session['username'])
    else:
        flash('Prosím, prihláste sa najprv.', 'warning')
        return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        flash('Prosím, prihláste sa najprv.', 'warning')
        return redirect(url_for('login'))

@app.route('/cpu_usage')
def cpu_usage():
    cpu_usage = psutil.cpu_percent(interval=1)
    return jsonify({'cpu_usage': cpu_usage})

@app.route('/ram_usage')
def ram_usage():
    ram = psutil.virtual_memory()
    ram_usage_percent = ram.percent
    ram_usage_gb = ram.used / (1024 ** 3)
    ram_total_gb = ram.total / (1024 ** 3)
    return jsonify(
        ram_usage_percent=ram_usage_percent,
        ram_usage_gb=round(ram_usage_gb, 2),
        ram_total_gb=round(ram_total_gb, 2)
    )

@app.route('/gpu_usage')
def gpu_usage():
    gpus = GPUtil.getGPUs()
    if gpus:
        gpu = gpus[0]  # Predpokladáme, že máte len jedno GPU
        gpu_usage_percent = gpu.load * 100
        vram_usage_gb = gpu.memoryUsed
        vram_total_gb = gpu.memoryTotal
    else:
        gpu_usage_percent = 0
        vram_usage_gb = 0
        vram_total_gb = 0
    return jsonify(
        gpu_usage_percent=round(gpu_usage_percent, 2),
        vram_usage_gb=round(vram_usage_gb, 2),
        vram_total_gb=round(vram_total_gb, 2)
    )

@app.route('/disk_usage')
def disk_usage():
    disk = psutil.disk_usage('/')
    disk_usage_percent = disk.percent
    disk_used_gb = disk.used / (1024 ** 3)
    disk_free_gb = disk.free / (1024 ** 3)
    return jsonify(
        disk_usage_percent=disk_usage_percent,
        disk_used_gb=round(disk_used_gb, 2),
        disk_free_gb=round(disk_free_gb, 2)
    )

@app.route('/network_usage')
def network_usage():
    # Získanie sieťových štatistík
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_recv = net_io.bytes_recv
    total_bytes = bytes_sent + bytes_recv
    total_gb = total_bytes / (1024 ** 3)

    # Percentuálne využitie (príklad: maximálna kapacita 1 Gbps)
    max_network_capacity = 1 * (1024 ** 3)  # 1 Gbps v bajtoch za sekundu
    network_usage_percent = (total_bytes / max_network_capacity) * 100

    # Získanie IP adresy
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    return jsonify(
        network_usage_percent=round(network_usage_percent, 2),
        total_gb=round(total_gb, 2),
        ip_address=ip_address
    )

@app.route('/console_log')
def console_log():
    # Získanie systémových údajov
    cpu_usage = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    ram_usage_percent = ram.percent
    disk = psutil.disk_usage('/')
    disk_usage_percent = disk.percent
    net_io = psutil.net_io_counters()
    total_bytes = net_io.bytes_sent + net_io.bytes_recv
    total_gb = total_bytes / (1024 ** 3)
    max_network_capacity = 1 * (1024 ** 3)  # 1 Gbps v bajtoch za sekundu
    network_usage_percent = (total_bytes / max_network_capacity) * 100
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)

    # Záznam správ do konzoly
    logger.info("System initialized.")
    logger.info(f"CPU usage at {cpu_usage}%.")
    logger.info(f"RAM usage at {ram_usage_percent}%.")
    logger.info(f"Disk usage at {disk_usage_percent}%.")
    logger.info(f"Network usage at {network_usage_percent}%.")
    logger.info(f"IP address: {ip_address}")

    # Vrátenie logov ako JSON odpoveď
    logs = [
        "[INFO] System initialized.",
        f"[INFO] CPU usage at {cpu_usage}%.",
        f"[INFO] RAM usage at {ram_usage_percent}%.",
        f"[INFO] Disk usage at {disk_usage_percent}%.",
        f"[INFO] Network usage at {network_usage_percent}%.",
        f"[INFO] IP address: {ip_address}"
    ]
    return jsonify(logs=logs)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not app.config['LOGIN_ENABLED']:
        flash('Prihlasovanie je momentálne vypnuté.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Skontroluj, či používateľ existuje v databáze
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['username'] = user.username
            flash('Úspešne ste sa prihlásili!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nesprávne prihlasovacie údaje. Skúste to znova.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not app.config['REGISTER_ENABLED']:
        flash('Registrácia je momentálne vypnutá.', 'info')
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Skontroluj, či používateľ už existuje
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Používateľ s týmto menom už existuje.', 'danger')
        else:
            # Zašifruj heslo a ulož používateľa do databázy
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = User(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Úspešne ste sa zaregistrovali! Teraz sa môžete prihlásiť.', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Úspešne ste sa odhlásili.', 'success')
    return redirect(url_for('home'))

@app.route('/scan_wifi', methods=['GET'])
def scan_wifi_endpoint():
    """Endpoint na skenovanie Wi-Fi sietí."""
    wifi_networks = scan_wifi()
    return jsonify(wifi_networks)

@app.route('/scan_bluetooth', methods=['GET'])
def scan_bluetooth_endpoint():
    """Endpoint na skenovanie Bluetooth zariadení."""
    bluetooth_devices = scan_bluetooth()
    return jsonify(bluetooth_devices)

@app.route('/connect_wifi', methods=['POST'])
def connect_wifi_endpoint():
    """Endpoint na pripojenie k Wi-Fi sieti."""
    ssid = request.json.get('ssid')
    password = request.json.get('password')
    result = connect_to_wifi(ssid, password)
    return jsonify(result)

@app.route('/connect_bluetooth', methods=['POST'])
def connect_bluetooth_endpoint():
    """Endpoint na pripojenie k Bluetooth zariadeniu."""
    mac_address = request.json.get('mac_address')
    result = connect_to_bluetooth(mac_address)
    return jsonify(result)

@app.route('/wifi')
def wifi():
    return render_template('wifi.html')

@app.route('/bluetooth')
def bluetooth():
    return render_template('bluetooth.html')


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Vytvorí tabuľky v databáze, ak ešte neexistujú
    app.run(debug=True)
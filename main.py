from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate 
import subprocess
import secrets
import string
from datetime import datetime, timedelta
from flask import flash
import ipaddress
import platform
import psutil
import socket



app = Flask(__name__)
app.secret_key = "your_secret_key"

# Configure SQL Alchemy
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users1.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax'
)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

pcs = [
    {"id": 1, "hostname": "PC1", "status": "Active", "ip_address": "192.168.1.1"},
    {"id": 2, "hostname": "PC2", "status": "Active", "ip_address": "192.168.1.2"},
    {"id": 3, "hostname": "PC3", "status": "Active", "ip_address": "192.168.1.3"},
    {"id": 4, "hostname": "PC4", "status": "Active", "ip_address": "192.168.1.4"},
    {"id": 5, "hostname": "PC5", "status": "Active", "ip_address": "192.168.1.5"},
    {"id": 6, "hostname": "PC6", "status": "Active", "ip_address": "192.168.1.6"}
]

# Define your network commands here
commands = {
    'Ping': 'ping',
    'Traceroute': 'traceroute',
    'Netstat': 'netstat',
    'Ifconfig': 'ifconfig',
    'Nslookup': 'nslookup',
    'Dig': 'dig',
    'Arp': 'arp',
    'Route': 'route',
    'IP (IP Address Show)': 'ip',
    'SSH': 'ssh',
    'SNMP': 'snmp',
    'Nmap': 'nmap',
    'Netstat': 'netstat',
    'Tcpdump': 'tcpdump',
    'Top': 'top',
    'Whois': 'whois',
    'Wget': 'wget'
}

# Database Model - Single Row with our DB
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    country = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    token = db.Column(db.String(50), unique=True, nullable=True)
    token_expiration = db.Column(db.DateTime, nullable=True)
    


    
    @property
    def is_admin_user(self):
        return self.username.endswith('.admin')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Node(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # actif/inactif  

    
class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
# Routes

@app.route("/admin/manage_courses")
def manage_courses():
    if "username" in session and session['is_admin']:
        courses = Course.query.all()
        return render_template("manage_courses.html", courses=courses)
    return redirect(url_for('home'))

@app.route("/admin/add_course", methods=["POST"])
def add_course():
    if "username" in session and session['is_admin']:
        title = request.form['title']
        description = request.form['description']
        new_course = Course(name=title, description=description)
        db.session.add(new_course)
        db.session.commit()
        flash("Course added successfully", "success")
        return redirect(url_for('manage_courses'))
    return redirect(url_for('home'))

@app.route("/admin/delete_course/<int:course_id>", methods=["POST"])
def delete_course(course_id):
    if "username" in session and session['is_admin']:
        course = Course.query.get(course_id)
        if course:
            db.session.delete(course)
            db.session.commit()
            flash(f"Course '{course.name}' has been deleted.", "success")
        else:
            flash("Course not found.", "error")
        return redirect(url_for('manage_courses'))
    return redirect(url_for('home'))

@app.route('/education')
def education():
    return render_template('education.html')

# Route for viewing a course
@app.route('/education/view-course')
def view_course():
    # Fetch courses from the database if necessary (for now, hardcoded example)
    courses = [
        {'title': 'Network Basics', 'description': 'Introduction to networking concepts'},
        {'title': 'CIDR Calculation', 'description': 'Understanding Classless Inter-Domain Routing'}
    ]
    return render_template('view_course.html', courses=courses)

@app.route('/network_visualization', methods=['GET'])
def network_visualization():
    if 'username' not in session or not session.get('is_privileged'):
        return jsonify({'error': 'Accès non autorisé'}), 403

    nodes = Node.query.all()  # Récupération de tous les nœuds du réseau
    return render_template('network_visualization.html', nodes=nodes)

# Route for searching tips (astuces)
@app.route('/education/search-tips', methods=['GET', 'POST'])
def search_tips():
    tips = [
        'Always keep your network updated.',
        'Use strong passwords.',
        'Monitor network traffic regularly.'
    ]
    if request.method == 'POST':
        keyword = request.form.get('keyword')
        filtered_tips = [tip for tip in tips if keyword.lower() in tip.lower()]
        return render_template('search_tips.html', tips=filtered_tips)
    return render_template('search_tips.html', tips=tips)

@app.route("/user_dashboard")
def user_dashboard():
    # Check if the user is logged in by checking the session
    if "username" in session:
        # Fetch the user object from the database
        user = User.query.filter_by(username=session['username']).first()

        # If the user exists in the database
        if user:
            # Define your network commands here
            commands = {
                'Ping': 'ping',
                'Traceroute': 'traceroute',
                'Netstat': 'netstat',
                'Ifconfig': 'ifconfig',
                'Nslookup': 'nslookup',
                'Dig': 'dig',
                'Arp': 'arp',
                'Route': 'route',
                'IP (IP Address Show)': 'ip',
                'SSH': 'ssh',
                'SNMP': 'snmp',
                'Nmap': 'nmap',
                'Tcpdump': 'tcpdump',
                'Top': 'top',
                'Wget': 'wget',
                'Whois': 'whois',
            }

            # Render the dashboard template with username and commands
            return render_template("user_dashboard.html", username=user.username, page_class="active", commands=commands)

        # If the user is not found in the database, clear the session and redirect to home
        else:
            session.pop('username', None)
            return redirect(url_for('home'))

    # If the user is not logged in (no session), redirect to home
    return redirect(url_for('home'))

@app.route("/check_user_info")
def check_user_info():
    if "username" not in session:
        return redirect(url_for('home'))
    return render_template("check_user_info.html", username=session['username'])


@app.route("/update_user_info", methods=["POST"])
def update_user_info():
    if "username" not in session:
        return jsonify({"error": "Not logged in", "success": False}), 401
    
    user = User.query.filter_by(username=session['username']).first()
    if not user:
        return jsonify({"error": "User not found", "success": False}), 404

    data = request.json
    if 'email' in data:
        user.email = data['email']
    
    if 'current_password' in data and 'new_password' in data:
        if user.check_password(data['current_password']):
            user.set_password(data['new_password'])
        else:
            return jsonify({"message": "Current password is incorrect", "success": False})

    db.session.commit()
    return jsonify({"message": "User information updated successfully", "success": True})

@app.route("/delete_user", methods=["POST"])
def delete_user():
    if "username" not in session:
        return jsonify({"error": "Not logged in"}), 401

    try:
        user = User.query.filter_by(username=session['username']).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Confirmation step for security (optional, but recommended)
        if request.json.get("confirm") != "YES":
            return jsonify({"message": "Please confirm account deletion by including 'confirm': 'YES' in your request body."}), 400

        db.session.delete(user)
        db.session.commit()
        session.clear()
        return jsonify({"message": "User deleted successfully"})
    except Exception as e:
        # Log the error for debugging
        print(f"Error deleting user: {e}")
        return jsonify({"error": "An error occurred. Please try again."}), 500

@app.route("/add_courses", methods=["POST"])
def add_courses():
    if "username" in session and session.get('is_admin'):
        name = request.form['name']
        description = request.form['description']
        new_course = Course(name=name, description=description)
        db.session.add(new_course)
        db.session.commit()
        flash("Course added successfully", "success")
        return redirect(url_for('manage_courses'))
    else:
        flash("You are not authorized to add courses.", "error")
        return redirect(url_for('user_dashboard'))


@app.route('/cidr_calculator', methods=['POST'])
def cidr_calculator():
    ip_cidr = request.form['cidr'].strip()  # Get the IP/CIDR from the form
    
    if not ip_cidr:
        return jsonify({'error': 'Please enter an IP address and CIDR notation.'})

    try:
        network = ipaddress.ip_network(ip_cidr, strict=False)

        result = {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'subnet_mask': str(network.netmask),
            'num_addresses': network.num_addresses
        }

        return jsonify(result)
    except ValueError:
        return jsonify({'error': 'Invalid IP address or CIDR notation.'})

@app.route("/signup")
def signup():
    countries = [
        'United States', 'Canada', 'United Kingdom', 'France', 'Germany',
        'Italy', 'Spain', 'Japan', 'China', 'Australia', 'Brazil', 'India', 'Tunisia'
    ]
    return render_template("signup.html", page_class="active", countries=countries)

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template("signin.html",page_class="active")

@app.route("/dashboard")
def dashboard():
    commands = {
        'Ping': 'ping',
        'Traceroute': 'traceroute',
        'Netstat': 'netstat',
        'Ifconfig': 'ifconfig',
        'Nslookup': 'nslookup',
        'Dig': 'dig',
        'Arp': 'arp',
        'Route': 'route',
        'IP (IP Address Show)': 'ip',
        'SSH': 'ssh',
        'SNMP': 'snmp',
        'Nmap': 'nmap',
        'Tcpdump': 'tcpdump',
        'Top': 'top',
        'Whois': 'whois',
        'Wget': 'wget',
    }

    if "username" in session:
        user = User.query.filter_by(username=session['username']).first()

        if session.get('is_admin'):
            return redirect(url_for('admin_dashboard'))
        
        # Check if user exists and has a token
        elif user and user.token:
            return redirect(url_for('privileged_dashboard', page_class="active"))
        else:
            return redirect(url_for('user_dashboard', page_class="active"))
    else:
        return redirect(url_for('home'))

@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    email = request.form['email']
    sex = request.form['sex']
    country = request.form['country']
    password = request.form["password"]

    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        flash("Username already exists. Please choose a different username.", "error")
        return redirect(url_for('signup'))

    # Check if email already exists
    existing_email = User.query.filter_by(email=email).first()
    if existing_email:
        flash("Email address is already registered. Please use a different email.", "error")
        return redirect(url_for('signup'))

    # If neither username nor email exist, create the new user
    new_user = User(username=username, email=email, sex=sex, country=country)
    new_user.set_password(password)
    new_user.is_admin = username.endswith('.admin')
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/get_ip', methods=['GET'])
def get_ip():
    ip_address = request.remote_addr
    return jsonify({'ip': ip_address})

@app.route("/signin", methods=["POST"])
def signin():
    username = request.form['username']
    password = request.form["password"]
    token = request.form.get("token", "")

    check_token_expiration()  # Check and remove expired tokens

    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        session['is_admin'] = user.is_admin_user
        if user.is_admin_user:
            return redirect(url_for('admin_dashboard'))
        elif user.token and token == user.token and user.token_expiration > datetime.utcnow():
            return redirect(url_for('privileged_dashboard'))
        elif token:
            # If a token was provided but it's invalid
            flash("Token not verified. Please try again or contact an administrator.", "error")
            return render_template("signin.html", error="Invalid token", page_class="active")
        else:
            return redirect(url_for('user_dashboard'))
    else:
        flash("Invalid username or password", "error")
        return render_template("signin.html", error="Invalid username or password", page_class="active")

@app.route("/admin_dashboard")
def admin_dashboard():
    if "username" in session and session['is_admin']:
        # Fetch the necessary data
        pcs = get_all_pcs()  # Replace this with your actual function to get PC data
        return render_template("admin_dashboard.html", username=session['username'], pcs=pcs, page_class="active")
    return redirect(url_for('home'))
def get_all_pcs():
    # This function should return a list of PCs. 
    # Replace the example data with your actual data retrieval logic.
    return [
        {'id': 1, 'ip': '192.168.1.10'},
        {'id': 2, 'ip': '192.168.1.11'},
        {'id': 3, 'ip': '192.168.1.12'},
        # Add more PCs as needed
    ]


@app.route("/privileged_dashboard")
def privileged_dashboard():
    if "username" in session and User.query.filter_by(username=session['username']).first().token:
        return render_template("privileged_dashboard.html", username=session['username'], page_class="active")
    return redirect(url_for('home'))



@app.route("/logout")
def logout():
    session.pop('username', None)
    session.pop('is_admin', None)
    return redirect(url_for('home'))

@app.route("/admin/manage_users")
def manage_users():
    if "username" in session and session['is_admin']:
        users = User.query.all()
        return render_template("manage_users.html", users=users, page_class="active")
    return redirect(url_for('home'))

@app.route("/admin/generate_token/<int:user_id>")
def generate_token(user_id):
    if "username" in session and session['is_admin']:
        user = User.query.get(user_id)
        if user:
            token = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            user.token = token
            user.token_expiration = datetime.utcnow() + timedelta(days=21)
            db.session.commit()
            flash(f"Token generated for user {user.username}. It will expire in 21 days.", "success")
            return redirect(url_for('manage_users'))
    return redirect(url_for('home'))

@app.route("/admin/delete_user/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if "username" in session and session['is_admin']:
        user = User.query.get(user_id)
        if user:
            if user.is_admin_user:
                flash(f"Cannot delete admin user {user.username}.", "error")
            else:
                db.session.delete(user)
                db.session.commit()
                flash(f"User {user.username} has been deleted from the database.", "success")
        else:
            flash("User not found.", "error")
        return redirect(url_for('manage_users'))
    return redirect(url_for('home'))

def check_token_expiration():
    expired_users = User.query.filter(User.token_expiration < datetime.utcnow()).all()
    for user in expired_users:
        user.token = None
        user.token_expiration = None
    db.session.commit()

@app.route("/ping_machine", methods=["POST"])
def ping_machine():
    ip_address = request.json.get("ip_address")
    
    # Check if the IP address is in the list of known PCs
    pc = next((pc for pc in pcs if pc["ip_address"] == ip_address), None)
    if not pc:
        return jsonify({"error": "IP address is not in the network."}), 400
    
    try:
        # Execute ping command
        result = subprocess.run(['ping', '-c', '4', ip_address], capture_output=True, text=True, timeout=10)
        return jsonify({"output": result.stdout})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# Route to get network information
@app.route("/network_info")
def network_info():
    # Exemple de données réseau pour la démonstration
    network = {
        "network_address": "192.168.1.0",
        "broadcast_address": "192.168.1.255",
        "subnet_mask": "255.255.255.0",
        "num_addresses": 254
    }

    # Extraire les adresses IP des PCs actifs
    active_ips = [pc["ip_address"] for pc in pcs if pc["status"] == "Active"]

    return jsonify({
        "network_address": network["network_address"],
        "broadcast_address": network["broadcast_address"],
        "subnet_mask": network["subnet_mask"],
        "total_hosts": network["num_addresses"] - 2,  # Exclure les adresses réseau et broadcast
        "available_ips": active_ips  # Affiche uniquement les IPs des PCs actifs
    }) 

@app.route('/')
def index_commands():
    # Liste des commandes réseau possibles
    commands = {
        'Ping': 'ping',
        'Traceroute': 'traceroute',
        'Netstat': 'netstat',
        'Ifconfig': 'ifconfig',
        'Nslookup': 'nslookup',
        'Dig': 'dig',
        'Arp': 'arp',
        'Route': 'route',
        'IP (IP Address Show)': 'ip',
        'SSH': 'ssh',
        'SNMP': 'snmp',
        'Nmap': 'nmap',
        'Netstat': 'netstat',
        'Tcpdump': 'tcpdump',
        'Top': 'top',
        'Wget': 'wget',
        'Whois': 'whois',
    }
    return render_template('user_dashboard.html', commands=commands)

@app.route('/execute', methods=['POST'])
def execute_command():
    command = request.form.get('command')
    target = request.form.get('target', '')

    # Security check: Ensure no unsafe inputs are passed
    if not target and command not in commands.values():
        return jsonify({"error": "Invalid command"}), 400

 # Construire la commande complète
    full_command = [command]
    if target:
        full_command.append(target)


    try:
        # Exécuter la commande en subprocess
        result = subprocess.run(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        output = result.stdout if result.stdout else result.stderr
        return jsonify({"output": output})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def execute_ping(target_ip):
    try:
        result = subprocess.run(
            ["ping", "-c", "4", "-W", "5", target_ip],  # Adjust for your OS (use '-n' for Windows)
            capture_output=True, text=True
        )
        if result.returncode == 0:
            return {"output": result.stdout}
        else:
            return {"error": "Ping failed: " + result.stderr}
    except Exception as e:
        return {"error": str(e)}


# Route pour récupérer les informations système
@app.route('/system_info', methods=['GET'])
def get_system_info():
    system_info = {
        "hostname": socket.gethostname(),
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "architecture": platform.architecture()[0],
        "cpu_cores": psutil.cpu_count(logical=False),
        "cpu_threads": psutil.cpu_count(logical=True),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "total_memory": f"{round(psutil.virtual_memory().total / (1024**3), 2)} GB",
        "available_memory": f"{round(psutil.virtual_memory().available / (1024**3), 2)} GB",
        "used_memory": f"{round(psutil.virtual_memory().used / (1024**3), 2)} GB",
        "memory_usage_percent": psutil.virtual_memory().percent,
    }
    return jsonify(system_info)

@app.route('/analyze_node/<node_id>', methods=['POST'])
def analyze_node(node_id):
    if 'username' not in session or not session.get('is_privileged'):
        return jsonify({'error': 'Accès non autorisé'}), 403
    
    node = Node.query.get(node_id)
    if not node:
        return jsonify({'error': 'Nœud non trouvé'}), 404
    
    # Simulation d'un test ping pour analyser l'état du nœud
    try:
        response = subprocess.check_output(['ping', '-c', '1', node.ip_address])
        node.status = 'actif'
    except subprocess.CalledProcessError:
        node.status = 'inactif'
    
    db.session.commit()
    return jsonify({'message': f'Nœud {node.ip_address} analysé avec succès', 'status': node.status})

# Route pour vérifier la sécurité des nœuds
@app.route('/check_security', methods=['POST'])
def check_security():
    if 'username' not in session or not session.get('is_privileged'):
        return jsonify({'error': 'Accès non autorisé'}), 403

    nodes = Node.query.all()
    insecure_nodes = []
    
    for node in nodes:
        result = subprocess.run(['nmap', '-p 22,80,443', node.ip_address], capture_output=True, text=True)
        if "open" in result.stdout:
            insecure_nodes.append(node.ip_address)
    
    return jsonify({
        'message': 'Vérification de la sécurité terminée',
        'insecure_nodes': insecure_nodes
    }) 
 

@app.route('/get_network_users')
def get_network_users():
    users = User.query.all()
    user_data = [{"id": user.id, "username": user.username} for user in users]
    return jsonify({"users": user_data})



if __name__ == "__main__":
    with app.app_context():
        #db.drop_all()
        db.create_all()
    app.run(debug=True)
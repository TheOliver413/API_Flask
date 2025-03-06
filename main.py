import socket
import requests
import smtplib
import psycopg2  # Conexión a PostgreSQL
from flask import Flask, request, jsonify
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import yagmail
from scapy.all import sr1, IP, ICMP, conf
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from newsapi import NewsApiClient #Libreria apra el uso de NewsApi
from datetime import datetime, timedelta



app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "your_secret_key"  # Cambia esto por una clave secreta segura
jwt = JWTManager(app)

# Conexión a la base de datos PostgreSQL
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host='localhost',
            user='postgres',
            password='admin',
            database='phishguard'
        )
        print("✅ Conexión a la base de datos establecida correctamente.")
        return conn
    except psycopg2.OperationalError as e:
        print("❌ Error de conexión a la base de datos:")
        print(e)
        return None
    except Exception as e:
        print("⚠️ Error inesperado:")
        print(e)
        return None

# Función para obtener la IP desde el dominio
def get_ip_from_url(url):
    try:
        ip = socket.gethostbyname(url)
        print("conn: ",ip)
        return ip
    except socket.gaierror as e:
        if e.errno == socket.EAI_NONAME:
            print(f"Error: No se pudo resolver el nombre del host para la URL '{url}'. Verifica que la URL esté correcta.")
        else:
            print(f"Error obteniendo la IP para la URL '{url}': {e}")
        return None

# Función para realizar el mapeo de red
def get_network_mapping(ip):
    try:
        conf.verb = 0
        packet = IP(dst=ip)/ICMP()
        response = sr1(packet, timeout=10)
        print("response: ",response)
        if response:
            return response.src
        else:
            print(f"No se recibió respuesta para el mapeo de red de la IP '{ip}'.")
            return None
    except Exception as e:
        print(f"Error realizando el mapeo de red para la IP '{ip}': {e}")
        return None

# Función para obtener información de hosting y DNS
def get_hosting_and_dns(url):
    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={url}")
        if response.status_code == 200:
            return response.text
        else:
            print(f"Error: El servidor respondió con el código de estado {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"Error obteniendo información de hosting y DNS para '{url}': {e}")
        return None

# Función para verificar la reputación del dominio
def check_domain_reputation(domain):
    api_key = '47f793dc503cb6166677dfaed965353820a70632f03b5be16dd129f9cba3b114'
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            # print("data: ",data)
            reputation = data['data']['attributes'].get('reputation', None)
            # print("reputation: ",reputation)
            if reputation and reputation < 0:
                return "Posible phishing (reputación negativa)."
            else:
                return "Reputación del dominio positiva."
        else:
            print(f"Error: El servidor respondió con el código de estado {response.status_code}")
            return "No se pudo verificar la reputación del dominio."
    except requests.RequestException as e:
        print(f"Error al verificar la reputación del dominio '{domain}': {e}")
        return "No se pudo verificar la reputación del dominio."

# Función para buscar patrones sospechosos en la URL
def check_phishing_patterns(url):
    phishing_keywords = ["login", "secure", "verify", "account", "update", "signin", "payment"]
    for keyword in phishing_keywords:
        if keyword in url.lower():
            return True
    return False
    
# Función para enviar un correo electrónico
def send_email(subject, body, recipient_email):        
     # Configura la cuenta
    yag = yagmail.SMTP("reportphishguard@gmail.com", "tnfj grul kawn ibxf")

    try:
        # Envía el correo
        yag.send(to=recipient_email, subject=subject, contents=body)
        print(f"Correo enviado a {recipient_email}")
        return "Correo enviado exitosamente"
    except yagmail.YagAddressError as address_error:
        print(f"Error en la dirección del correo: {address_error}")
        return f"Error en la dirección del correo: {address_error}"
    except yagmail.YagConnectionClosed as conn_error:
        print(f"Error de conexión: {conn_error}")
        return f"Error de conexión: {conn_error}"
    except Exception as e:
        print(f"Error enviando correo: {e}")
        return f"Error enviando correo: {e}"

# Función para guardar resultados en la tabla 'urls'
def save_url_and_analysis(url, ip, phishing_message, reputation_result):
    conn = get_db_connection()
    cur = conn.cursor()

    # Verificar si la URL ya está en la base de datos
    cur.execute("SELECT url_id FROM urls WHERE url = %s", (url,))
    result = cur.fetchone()

    if not result:
        # Si no existe, insertar la nueva entrada en 'urls'
        cur.execute("""
            INSERT INTO urls (url, status, risk_percentage)
            VALUES (%s, %s, %s)
            RETURNING url_id
        """, (url, phishing_message, calcular_riesgo(phishing_message, reputation_result)))
        url_id = cur.fetchone()[0]
    else:
        # Si ya existe, recuperar su url_id
        url_id = result[0]

    # Insertar el análisis asociado en la tabla 'analisis'
    cur.execute("""
        INSERT INTO analysis (url_id, traceroute_result, methodology, risk_percentage)
        VALUES (%s, %s, %s, %s)
    """, (url_id, "Traceroute result placeholder", "Metodología utilizada", calcular_riesgo(phishing_message, reputation_result)))

    conn.commit()
    cur.close()
    conn.close()

# Función auxiliar para calcular el riesgo basado en la reputación y el phishing detectado
def calcular_riesgo(phishing_message, reputation_result):
    riesgo = 0
    if "phishing" in phishing_message:
        riesgo += 50
    if "Posible phishing" in reputation_result:
        riesgo += 50
        
        print("riesgo: ",riesgo)
    return riesgo

@app.route('/validate_url', methods=['POST'])
def validate_url():
    data = request.json
    url = data.get('url')
    email = data.get('email')
    
    if not url:
        return jsonify({'error': 'No URL provided'}), 400
    
    domain = url.split("//")[1].split('/')[0]
    
    # Obtener IP
    ip = get_ip_from_url(domain)
    if not ip:
        return jsonify({'error': 'No se pudo resolver la IP'}), 400
    
    # Verificar patrones de phishing
    phishing_detected = check_phishing_patterns(url)
    
    phishing_message = "La URL contiene patrones comunes de phishing." if phishing_detected else "La URL no contiene patrones comunes de phishing."
    
    # Verificar reputación
    reputation_result = check_domain_reputation(domain)
    
    # Mapeo de red
    network_mapping_result = get_network_mapping(ip)

    # Guardar resultados en la base de datos si no existe
    save_url_and_analysis(url, ip, phishing_message, reputation_result)
    
    # Enviar correo si se detecta phishing
    if phishing_detected:
        subject = "Alerta de Phishing"
        body = f"Se ha detectado posible phishing en la URL: {url}\nDetalles:\nDominio: {domain}\nIP: {ip}\nMensaje: {phishing_message}\nReputación: {reputation_result}"
        send_email(subject, body, email)

    # Responder con los resultados
    return jsonify({
        'domain': domain,
        'ip': ip,
        'phishing_message': phishing_message,
        'reputation_result': reputation_result
    })
# Registro de un nuevo usuario
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role')

    if not username or not password or not email:
        return jsonify({'msg': 'Faltan datos en la solicitud'}), 400

    hashed_password = generate_password_hash(password)

    # Conexión a la base de datos
    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Error de conexión a la base de datos'}), 500  # Retorna un error HTTP 500

    try:
        cur = conn.cursor()

        # Verificar si el usuario ya existe
        cur.execute("SELECT user_id FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        if user:
            cur.close()
            conn.close()
            return jsonify({'msg': 'Usuario ya existe'}), 400

        # Crear el nuevo usuario
        cur.execute("INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s) RETURNING user_id", 
                    (username, hashed_password, email, role))
        conn.commit()

        user_id = cur.fetchone()[0]
        cur.close()
        conn.close()

        return jsonify({'msg': 'Usuario registrado exitosamente', 'user_id': user_id}), 201
    
    except psycopg2.Error as e:
        print("❌ Error en la consulta SQL:", e)
        return jsonify({'msg': 'Error en la base de datos', 'error': str(e)}), 500
    except Exception as e:
        print("⚠️ Error inesperado:", e)
        return jsonify({'msg': 'Error interno del servidor', 'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

# Login de usuario
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'msg': 'Faltan datos en la solicitud'}), 400

    # Conexión a la base de datos
    conn = get_db_connection()
    cur = conn.cursor()

    # Verificar si el usuario existe y obtener todos los datos
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()

    if not user or not check_password_hash(user[3], password):
        return jsonify({'msg': 'Credenciales incorrectas'}), 401

    user_data = {
        'user_id': user[0],
        'username': user[1],
        'email': user[2],
        'role': user[3],
        'passwors': user[4]
    }

    # Crear el token JWT
    access_token = create_access_token(identity=user_data['user_id'])

    cur.close()
    conn.close()

    return jsonify({'msg': 'Login exitoso', 'access_token': access_token, 'user': user_data})


# Ruta protegida que requiere autenticación JWT
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    # Obtener la identidad del usuario desde el JWT
    current_user = get_jwt_identity()
    return jsonify({'msg': f'Acceso permitido, usuario {current_user}'})

@app.route('/send-email', methods=['POST'])
def send_email_route():
    try:
        data = request.get_json()
        subject = data.get('subject')
        body = data.get('body')
        recipient_email = data.get('recipient_email')

        if not subject or not body or not recipient_email:
            return jsonify({"message": "Faltan parámetros obligatorios"}), 400

        result = send_email(subject, body, recipient_email)
        if "Error" in result:
            return jsonify({"message": result}), 500
        return jsonify({"message": "Correo enviado exitosamente"}), 200

    except Exception as e:
        print(f"Error en la ruta: {e}")
        return jsonify({"message": "Error en el servidor"}), 500
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
    
    
    
#---------------------------------------------------------------------------------
#--------------------------------  NEWS API --------------------------------------
#---------------------------------------------------------------------------------

newsapi = NewsApiClient(api_key='ad037202cf534cacb580a1fb12c97eb4')


@app.route('/news', methods=['GET'])
def searchs_news():
    try:
        # Obtener parámetros de la petición (siempre en español)
        query = request.args.get('query', 'ciberseguridad')
        sort_by = request.args.get('sort_by', 'relevancy')
        page = int(request.args.get('page', 1))
        
        # Calcular fecha de "desde" (por defecto 30 días atrás)
        days_back = int(request.args.get('days', 30))
        from_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y-%m-%d')
        
        # Realizar consulta a NewsAPI siempre en español
        all_articles = newsapi.get_everything(
            q=query,
            from_param=from_date,
            language='es',
            sort_by=sort_by,
            page=page
        )
        
        # Crear respuesta con los resultados y parámetros
        response = {
            'data': all_articles,
            'parameters': {
                'query': query,
                'language': 'es',
                'sort_by': sort_by,
                'page': page,
                'from_date': from_date
            }
        }
        
        return jsonify(response)
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'parameters': request.args
        }), 500

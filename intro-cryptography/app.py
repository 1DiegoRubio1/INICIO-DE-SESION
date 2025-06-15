"""
Sistema de Inicio de Sesión con Criptografía
Instituto Politécnico Nacional - ESCOM
Práctica: Introduction to Cryptography

Archivo: app.py
Descripción: Aplicación principal Flask con todas las funcionalidades

Características implementadas:
- Hash SHA-256 del lado del cliente
- PBKDF2 con salt en el servidor
- Verificación por correo electrónico
- Restablecimiento seguro de contraseñas
- Generación de PDFs con datos criptográficos
- Dashboard completo del usuario
- Logs de auditoría de seguridad
"""

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import secrets
import datetime
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
import io
import logging

# Configuración de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuración de la aplicación
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'clave-segura-para-desarrollo')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///crypto_users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuración de correo electrónico
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'tu-email@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'tu-password-app')

# Inicialización de extensiones
db = SQLAlchemy(app)
mail = Mail(app)

# ========================= MODELOS DE BASE DE DATOS =========================

class User(db.Model):
    """
    Modelo de usuario con campos de seguridad
    """
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    reset_token = db.Column(db.String(100), unique=True)
    reset_token_expiry = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relación con intentos de login
    login_attempts = db.relationship('LoginAttempt', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class LoginAttempt(db.Model):
    """
    Modelo para registrar intentos de inicio de sesión
    """
    __tablename__ = 'login_attempts'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    username_attempted = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    
    def __repr__(self):
        return f'<LoginAttempt {self.username_attempted} at {self.timestamp}>'

# ========================= GESTIÓN CRIPTOGRÁFICA =========================

class CryptoManager:
    """
    Gestor centralizado de todas las funciones criptográficas del sistema
    
    Implementa:
    - SHA-256 para hash del lado del cliente (256 bits de seguridad)
    - PBKDF2 para hash del servidor con salt automático
    - Generación segura de tokens (256 bits de entropía)
    """
    
    @staticmethod
    def generate_client_hash(password):
        """
        Simula el hash SHA-256 que se realiza en el cliente
        
        Parámetros de SHA-256:
        - Familia: SHA-2 (Secure Hash Algorithm 2)
        - Tamaño del digest: 256 bits (32 bytes)
        - Seguridad ante ataques de preimagen: 256 bits
        - Seguridad ante ataques de colisión: 128 bits
        - Función resistente a extensión de longitud: Sí
        
        Args:
            password (str): Contraseña en texto plano
            
        Returns:
            str: Hash hexadecimal de 64 caracteres
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    @staticmethod
    def generate_server_hash(client_hash):
        """
        Genera hash seguro para almacenamiento en servidor
        
        Utiliza PBKDF2 (Password-Based Key Derivation Function 2) implementado
        en Werkzeug con las siguientes características:
        - Algoritmo base: SHA-256
        - Iteraciones: 260,000+ (ajustado automáticamente)
        - Salt: 16 bytes generado aleatoriamente
        - Formato: pbkdf2:sha256:iteraciones$salt$hash
        
        Args:
            client_hash (str): Hash SHA-256 del cliente
            
        Returns:
            str: Hash PBKDF2 con salt para almacenamiento seguro
        """
        return generate_password_hash(client_hash, method='pbkdf2:sha256')
    
    @staticmethod
    def verify_password(client_hash, stored_hash):
        """
        Verifica contraseña comparando hash del cliente con hash almacenado
        
        Args:
            client_hash (str): Hash SHA-256 del cliente
            stored_hash (str): Hash PBKDF2 almacenado en BD
            
        Returns:
            bool: True si las contraseñas coinciden
        """
        return check_password_hash(stored_hash, client_hash)
    
    @staticmethod
    def generate_secure_token():
        """
        Genera token criptográficamente seguro
        
        Utiliza el módulo secrets de Python para generar tokens seguros:
        - Entropía: 256 bits
        - Codificación: URL-safe base64
        - Longitud resultante: 43 caracteres
        - Resistente a ataques de adivinanza
        
        Returns:
            str: Token seguro de 43 caracteres
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def is_token_expired(created_time, hours=24):
        """
        Verifica si un token ha expirado
        
        Args:
            created_time (datetime): Momento de creación del token
            hours (int): Horas antes de expiración
            
        Returns:
            bool: True si el token ha expirado
        """
        if not created_time:
            return True
        
        expiry_time = created_time + datetime.timedelta(hours=hours)
        return datetime.datetime.utcnow() > expiry_time

# ========================= SERVICIOS DE CORREO =========================

class EmailService:
    """
    Servicio para el envío de correos electrónicos con plantillas HTML
    
    Características de seguridad:
    - No revela información del usuario en notificaciones
    - Tokens con expiración automática
    - Plantillas profesionales con información técnica
    """
    
    @staticmethod
    def send_verification_email(user_email, username, token):
        """
        Envía correo de verificación de cuenta
        
        Args:
            user_email (str): Correo del destinatario
            username (str): Nombre de usuario
            token (str): Token de verificación único
            
        Returns:
            bool: True si el correo se envió exitosamente
        """
        try:
            msg = Message(
                '🔐 Verificación de Cuenta - Crypto Login System',
                sender=app.config['MAIL_USERNAME'],
                recipients=[user_email]
            )
            
            verification_url = url_for('verify_email', token=token, _external=True)
            
            msg.html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; }}
                    .content {{ padding: 30px; line-height: 1.6; }}
                    .button {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; font-weight: bold; }}
                    .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
                    .security-info {{ background: #e9ecef; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔐 Crypto Login System</h1>
                        <p>Instituto Politécnico Nacional - ESCOM</p>
                    </div>
                    <div class="content">
                        <h2>¡Hola {username}!</h2>
                        <p>Gracias por registrarte en nuestro sistema de autenticación criptográfica.</p>
                        <p>Para completar tu registro y activar tu cuenta, por favor verifica tu correo electrónico:</p>
                        
                        <div style="text-align: center;">
                            <a href="{verification_url}" class="button">✅ Verificar Correo Electrónico</a>
                        </div>
                        
                        <div class="security-info">
                            <h3>🛡️ Información de Seguridad:</h3>
                            <ul>
                                <li><strong>Hash utilizado:</strong> SHA-256 (cliente) + PBKDF2 (servidor)</li>
                                <li><strong>Token de verificación:</strong> 256 bits de entropía</li>
                                <li><strong>Expiración:</strong> 24 horas</li>
                                <li><strong>Comunicación:</strong> TLS 1.2+</li>
                            </ul>
                        </div>
                        
                        <p><strong>⚠️ Importante:</strong> Este enlace expirará en 24 horas por motivos de seguridad.</p>
                    </div>
                    <div class="footer">
                        <p>Este correo fue generado automáticamente. No respondas a este mensaje.</p>
                        <p>Sistema desarrollado para la materia Introduction to Cryptography</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            mail.send(msg)
            logger.info(f"Correo de verificación enviado a {user_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando correo de verificación: {e}")
            return False
    
    @staticmethod
    def send_reset_email(user_email, username, token):
        """
        Envía correo de restablecimiento de contraseña
        
        Args:
            user_email (str): Correo del destinatario
            username (str): Nombre de usuario
            token (str): Token de restablecimiento único
            
        Returns:
            bool: True si el correo se envió exitosamente
        """
        try:
            msg = Message(
                '🔑 Restablecimiento de Contraseña - Crypto Login System',
                sender=app.config['MAIL_USERNAME'],
                recipients=[user_email]
            )
            
            reset_url = url_for('reset_password', token=token, _external=True)
            
            msg.html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: white; border-radius: 10px; overflow: hidden; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
                    .header {{ background: linear-gradient(135deg, #FF6B35 0%, #F7931E 100%); color: white; padding: 30px; text-align: center; }}
                    .content {{ padding: 30px; line-height: 1.6; }}
                    .button {{ background: linear-gradient(135deg, #FF6B35 0%, #F7931E 100%); color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; font-weight: bold; }}
                    .warning {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }}
                    .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔑 Restablecimiento de Contraseña</h1>
                        <p>Crypto Login System - ESCOM</p>
                    </div>
                    <div class="content">
                        <h2>¡Hola {username}!</h2>
                        <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.</p>
                        
                        <div class="warning">
                            <strong>⚠️ Importante:</strong> Si no solicitaste este cambio, ignora este correo y tu cuenta permanecerá segura.
                        </div>
                        
                        <p>Para crear una nueva contraseña, haz clic en el siguiente botón:</p>
                        
                        <div style="text-align: center;">
                            <a href="{reset_url}" class="button">🔒 Restablecer Contraseña</a>
                        </div>
                        
                        <p><strong>⏰ Este enlace expirará en 1 hora</strong> por motivos de seguridad.</p>
                        
                        <p>Si tienes problemas con el botón, copia y pega este enlace en tu navegador:</p>
                        <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px;">
                            {reset_url}
                        </p>
                    </div>
                    <div class="footer">
                        <p>Este correo fue generado automáticamente. No respondas a este mensaje.</p>
                        <p>Si no solicitaste este cambio, tu cuenta permanece segura.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            mail.send(msg)
            logger.info(f"Correo de restablecimiento enviado a {user_email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando correo de restablecimiento: {e}")
            return False

# ========================= GENERADOR DE PDFs =========================

class PDFGenerator:
    """
    Generador de documentos PDF con información criptográfica
    """
    
    @staticmethod
    def generate_crypto_facts_pdf():
        """
        Genera PDF con datos curiosos y técnicos de criptografía
        
        Returns:
            io.BytesIO: Buffer con el PDF generado
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer, 
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Estilos personalizados
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=HexColor('#667eea'),
            alignment=1  # Centrado
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            textColor=HexColor('#764ba2')
        )
        
        story = []
        
        # Título principal
        title = Paragraph("🔐 Datos Curiosos de Criptografía", title_style)
        story.append(title)
        
        subtitle = Paragraph("Instituto Politécnico Nacional - ESCOM<br/>Introduction to Cryptography", styles['Normal'])
        story.append(subtitle)
        story.append(Spacer(1, 30))
        
        # Datos curiosos numerados
        facts = [
            {
                "title": "1. El Cifrado César - Simplicidad Histórica",
                "content": """
                Julio César utilizaba un cifrado de sustitución simple donde cada letra se desplazaba 
                3 posiciones en el alfabeto. Aunque rudimentario para los estándares actuales, fue 
                efectivo para su época y sentó las bases conceptuales de muchos cifrados modernos. 
                La clave residía en la simplicidad: 'A' se convertía en 'D', 'B' en 'E', etc.
                """
            },
            {
                "title": "2. La Máquina Enigma - Complejidad y Ruptura",
                "content": """
                Durante la Segunda Guerra Mundial, la máquina Enigma alemana tenía más de 150 trillones 
                de configuraciones posibles gracias a sus rotores mecánicos y panel de conexiones. 
                Sin embargo, fue descifrada por el equipo de Alan Turing en Bletchley Park, Gran Bretaña, 
                gracias a errores operacionales alemanes y al poder del análisis criptográfico sistemático.
                """
            },
            {
                "title": "3. SHA-256 y la Revolución Blockchain",
                "content": """
                El algoritmo SHA-256 que implementamos en nuestro sistema también es fundamental para 
                Bitcoin y otras criptomonedas. Cada bloque en la blockchain requiere encontrar un hash 
                SHA-256 que comience con múltiples ceros consecutivos, lo que requiere enormes cantidades 
                de poder computacional y garantiza la seguridad de la red distribuida.
                """
            },
            {
                "title": "4. Criptografía Cuántica - El Futuro de la Seguridad",
                "content": """
                Los computadores cuánticos representan tanto una amenaza como una oportunidad para la 
                criptografía. Podrían romper RSA y otros algoritmos de clave pública actuales usando el 
                algoritmo de Shor, pero también nos proporcionan la criptografía cuántica, que es 
                teóricamente inquebrantable debido a las leyes fundamentales de la mecánica cuántica.
                """
            },
            {
                "title": "5. One-Time Pad - La Perfección Matemática",
                "content": """
                El cifrado de 'one-time pad' o 'libreta de un solo uso' es el único cifrado matemáticamente 
                probado como inquebrantable (perfect secrecy), siempre que se cumplan tres condiciones: 
                la clave debe ser verdaderamente aleatoria, tan larga como el mensaje, y usarse solo una vez. 
                Fue utilizado en comunicaciones diplomáticas de alta seguridad durante la Guerra Fría.
                """
            }
        ]
        
        for fact in facts:
            # Título del dato curioso
            fact_title = Paragraph(fact["title"], heading_style)
            story.append(fact_title)
            story.append(Spacer(1, 10))
            
            # Contenido del dato curioso
            fact_content = Paragraph(fact["content"].strip(), styles['Normal'])
            story.append(fact_content)
            story.append(Spacer(1, 20))
        
        # Información técnica del sistema
        tech_title = Paragraph("Información Técnica del Sistema Implementado", heading_style)
        story.append(tech_title)
        story.append(Spacer(1, 10))
        
        tech_content = Paragraph("""
        <b>Arquitectura de Seguridad Multicapa:</b><br/><br/>
        
        <b>• Hash del Lado del Cliente (SHA-256):</b><br/>
        - Algoritmo: SHA-256 (Secure Hash Algorithm 256-bit)<br/>
        - Familia: SHA-2<br/>
        - Tamaño del digest: 256 bits (32 bytes)<br/>
        - Seguridad ante preimagen: 256 bits<br/>
        - Seguridad ante colisión: 128 bits<br/>
        - Implementación: CryptoJS en JavaScript<br/><br/>
        
        <b>• Hash del Lado del Servidor (PBKDF2):</b><br/>
        - Algoritmo base: SHA-256<br/>
        - Iteraciones: 260,000+ (ajustado dinámicamente)<br/>
        - Salt: 16 bytes aleatorios por contraseña<br/>
        - Implementación: Werkzeug (Python)<br/><br/>
        
        <b>• Generación de Tokens Seguros:</b><br/>
        - Entropía: 256 bits<br/>
        - Codificación: URL-safe Base64<br/>
        - Longitud: 43 caracteres<br/>
        - Uso: Verificación de email y reset de contraseña<br/><br/>
        
        <b>• Comunicación Segura:</b><br/>
        - Protocolo recomendado: HTTPS/TLS 1.2+<br/>
        - Protección en tránsito de todas las comunicaciones<br/>
        - Validación de certificados SSL<br/><br/>
        
        <b>• Base de Datos:</b><br/>
        - Motor: SQLite (desarrollo) / PostgreSQL (producción)<br/>
        - Almacenamiento seguro de hashes con salt<br/>
        - Registro de intentos de acceso para auditoría<br/>
        - Tokens de sesión con expiración automática
        """, styles['Normal'])
        story.append(tech_content)
        
        # Generar el PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

# ========================= RUTAS DE LA APLICACIÓN =========================

@app.route('/')
def index():
    """
    Página principal con datos curiosos de criptografía e información del sistema
    """
    crypto_facts = [
        {
            "title": "SHA-256 en Blockchain",
            "description": "El mismo algoritmo que protege tus contraseñas aquí también asegura Bitcoin con 256 bits de seguridad criptográfica.",
            "icon": "🔗"
        },
        {
            "title": "Criptografía Cuántica",
            "description": "La próxima generación de cifrado utiliza las leyes de la física cuántica para crear comunicaciones teóricamente inquebrantables.",
            "icon": "⚛️"
        },
        {
            "title": "Máquina Enigma",
            "description": "Con 150 trillones de configuraciones posibles, fue descifrada por Alan Turing durante la Segunda Guerra Mundial.",
            "icon": "🎛️"
        }
    ]
    
    return render_template('index.html', facts=crypto_facts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Registro de usuarios con verificación por correo electrónico
    Implementa hash SHA-256 del lado del cliente
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            email = data.get('email', '').strip().lower()
            client_hash = data.get('password_hash', '')
            
            # Validaciones de entrada
            if not username or not email or not client_hash:
                return jsonify({'success': False, 'message': 'Todos los campos son obligatorios'})
            
            if len(username) < 3 or len(username) > 20:
                return jsonify({'success': False, 'message': 'El usuario debe tener entre 3 y 20 caracteres'})
            
            if len(client_hash) != 64:  # SHA-256 produce 64 caracteres hexadecimales
                return jsonify({'success': False, 'message': 'Error en el hash de la contraseña'})
            
            # Verificar si el usuario ya existe
            if User.query.filter_by(username=username).first():
                return jsonify({'success': False, 'message': 'El nombre de usuario ya está en uso'})
            
            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'El correo electrónico ya está registrado'})
            
            # Crear hash del servidor usando PBKDF2
            server_hash = CryptoManager.generate_server_hash(client_hash)
            verification_token = CryptoManager.generate_secure_token()
            
            # Crear nuevo usuario
            user = User(
                username=username,
                email=email,
                password_hash=server_hash,
                verification_token=verification_token
            )
            
            db.session.add(user)
            db.session.commit()
            
            logger.info(f"Usuario registrado: {username} ({email})")
            
            # Enviar correo de verificación
            if EmailService.send_verification_email(email, username, verification_token):
                return jsonify({
                    'success': True, 
                    'message': 'Usuario registrado exitosamente. Revisa tu correo para verificar tu cuenta.'
                })
            else:
                return jsonify({
                    'success': False, 
                    'message': 'Usuario registrado pero no se pudo enviar el correo de verificación'
                })
                
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error en registro: {e}")
            return jsonify({'success': False, 'message': 'Error interno del servidor'})
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Inicio de sesión con verificación de hash del cliente
    Registra todos los intentos para auditoría de seguridad
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            username = data.get('username', '').strip()
            client_hash = data.get('password_hash', '')
            
            # Buscar usuario
            user = User.query.filter_by(username=username).first()
            
            # Registrar intento de login
            attempt = LoginAttempt(
                user_id=user.id if user else None,
                username_attempted=username,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')[:200],
                success=False
            )
            
            # Verificar credenciales
            if user and user.is_verified and CryptoManager.verify_password(client_hash, user.password_hash):
                # Login exitoso
                session['user_id'] = user.id
                session['username'] = user.username
                
                # Actualizar último login
                user.last_login = datetime.datetime.utcnow()
                attempt.success = True
                
                db.session.add(attempt)
                db.session.commit()
                
                logger.info(f"Login exitoso: {username} desde {request.remote_addr}")
                return jsonify({'success': True, 'message': 'Inicio de sesión exitoso'})
            else:
                # Login fallido
                db.session.add(attempt)
                db.session.commit()
                
                if user and not user.is_verified:
                    logger.warning(f"Login fallido - cuenta no verificada: {username}")
                    return jsonify({
                        'success': False, 
                        'message': 'Por favor verifica tu correo electrónico antes de iniciar sesión'
                    })
                else:
                    logger.warning(f"Login fallido - credenciales inválidas: {username} desde {request.remote_addr}")
                    return jsonify({'success': False, 'message': 'Usuario o contraseña incorrectos'})
                    
        except Exception as e:
            logger.error(f"Error en login: {e}")
            return jsonify({'success': False, 'message': 'Error interno del servidor'})
    
    return render_template('login.html')

@app.route('/verify_email/<token>')
def verify_email(token):
    """
    Verificación de correo electrónico mediante token único
    
    Args:
        token (str): Token de verificación de 256 bits
    """
    try:
        user = User.query.filter_by(verification_token=token).first()
        
        if user:
            # Verificar si el token no ha expirado (24 horas)
            if not CryptoManager.is_token_expired(user.created_at, 24):
                user.is_verified = True
                user.verification_token = None
                db.session.commit()
                
                logger.info(f"Email verificado exitosamente: {user.username}")
                flash('¡Correo verificado exitosamente! Ahora puedes iniciar sesión.', 'success')
            else:
                logger.warning(f"Token de verificación expirado para: {user.username}")
                flash('El enlace de verificación ha expirado. Solicita un nuevo registro.', 'error')
        else:
            logger.warning(f"Token de verificación inválido: {token[:10]}...")
            flash('Enlace de verificación inválido o ya utilizado.', 'error')
            
    except Exception as e:
        logger.error(f"Error en verificación de email: {e}")
        flash('Error al verificar el correo electrónico.', 'error')
    
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Solicitud de restablecimiento de contraseña
    Por seguridad, no revela si el email existe en el sistema
    """
    if request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email', '').strip().lower()
            
            user = User.query.filter_by(email=email).first()
            
            if user and user.is_verified:
                # Generar token de restablecimiento con expiración
                reset_token = CryptoManager.generate_secure_token()
                user.reset_token = reset_token
                user.reset_token_expiry = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
                db.session.commit()
                
                # Enviar correo de restablecimiento
                if EmailService.send_reset_email(email, user.username, reset_token):
                    logger.info(f"Correo de restablecimiento enviado a: {email}")
                else:
                    logger.error(f"Error enviando correo de restablecimiento a: {email}")
            
            # Respuesta genérica por seguridad (no revela si el email existe)
            return jsonify({
                'success': True, 
                'message': 'Si el correo está registrado, recibirás instrucciones para restablecer tu contraseña.'
            })
            
        except Exception as e:
            logger.error(f"Error en forgot_password: {e}")
            return jsonify({'success': False, 'message': 'Error interno del servidor'})
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """
    Restablecimiento de contraseña con token temporal
    
    Args:
        token (str): Token de restablecimiento de 256 bits
    """
    user = User.query.filter_by(reset_token=token).first()
    
    # Verificar validez del token
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.datetime.utcnow():
        flash('El enlace de restablecimiento es inválido o ha expirado.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            data = request.get_json()
            new_client_hash = data.get('password_hash', '')
            
            if len(new_client_hash) != 64:  # Verificar hash SHA-256 válido
                return jsonify({'success': False, 'message': 'Error en el hash de la contraseña'})
            
            # Actualizar contraseña con nuevo hash
            user.password_hash = CryptoManager.generate_server_hash(new_client_hash)
            user.reset_token = None
            user.reset_token_expiry = None
            db.session.commit()
            
            logger.info(f"Contraseña restablecida para usuario: {user.username}")
            return jsonify({'success': True, 'message': 'Contraseña actualizada exitosamente'})
            
        except Exception as e:
            logger.error(f"Error en reset_password: {e}")
            return jsonify({'success': False, 'message': 'Error interno del servidor'})
    
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    """
    Panel de control del usuario autenticado
    Muestra información de la cuenta y historial de accesos
    """
    if 'user_id' not in session:
        flash('Debes iniciar sesión para acceder al dashboard.', 'error')
        return redirect(url_for('login'))
    
    try:
        user = User.query.get(session['user_id'])
        if not user:
            session.clear()
            flash('Sesión inválida. Por favor inicia sesión nuevamente.', 'error')
            return redirect(url_for('login'))
        
        # Obtener últimos intentos de login
        recent_attempts = LoginAttempt.query.filter_by(
            user_id=user.id
        ).order_by(
            LoginAttempt.timestamp.desc()
        ).limit(10).all()
        
        return render_template('dashboard.html', user=user, attempts=recent_attempts)
        
    except Exception as e:
        logger.error(f"Error en dashboard: {e}")
        flash('Error cargando el dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/download_pdf')
def download_pdf():
    """
    Descarga PDF con datos curiosos de criptografía
    Solo disponible para usuarios autenticados
    """
    if 'user_id' not in session:
        flash('Debes iniciar sesión para descargar el PDF.', 'error')
        return redirect(url_for('login'))
    
    try:
        user = User.query.get(session['user_id'])
        pdf_buffer = PDFGenerator.generate_crypto_facts_pdf()
        
        logger.info(f"PDF descargado por usuario: {user.username}")
        
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=f'datos_curiosos_criptografia_{datetime.datetime.now().strftime("%Y%m%d")}.pdf',
            mimetype='application/pdf'
        )
        
    except Exception as e:
        logger.error(f"Error generando PDF: {e}")
        flash('Error generando el PDF.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """
    Cerrar sesión y limpiar datos de sesión
    """
    username = session.get('username', 'Usuario desconocido')
    session.clear()
    logger.info(f"Logout exitoso: {username}")
    flash('Sesión cerrada exitosamente.', 'success')
    return redirect(url_for('index'))

# ========================= MANEJO DE ERRORES =========================

@app.errorhandler(404)
def not_found_error(error):
    """Manejo de errores 404"""
    return render_template('base.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejo de errores 500"""
    db.session.rollback()
    logger.error(f"Error interno del servidor: {error}")
    return render_template('base.html'), 500

# ========================= INICIALIZACIÓN =========================

def init_database():
    """
    Inicializa la base de datos y crea las tablas necesarias
    """
    try:
        db.create_all()
        logger.info("Base de datos inicializada correctamente")
        
        # Verificar si hay usuarios en el sistema
        user_count = User.query.count()
        logger.info(f"Usuarios registrados en el sistema: {user_count}")
        
    except Exception as e:
        logger.error(f"Error inicializando base de datos: {e}")

# ========================= PUNTO DE ENTRADA =========================

if __name__ == '__main__':
    with app.app_context():
        init_database()
    
    logger.info("Iniciando Crypto Login System...")
    logger.info("Sistema desarrollado para IPN-ESCOM - Introduction to Cryptography")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
"""
Configuración del Sistema de Inicio de Sesión Criptográfico
"""

import os
from datetime import timedelta

class Config:
    # Configuración básica
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'tu-clave-secreta-muy-segura-cambiala'
    
    # Base de datos
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///crypto_users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Configuración de correo (Gmail)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')  # tu-email@gmail.com
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')  # contraseña de aplicación
    
    # Seguridad
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    WTF_CSRF_ENABLED = True
    
    # Configuración de tokens
    TOKEN_EXPIRATION_HOURS = 24  # Verificación de email
    RESET_TOKEN_EXPIRATION_HOURS = 1  # Reset de contraseña
#!/usr/bin/env python3
"""
Script de ejecución para el Sistema de Inicio de Sesión Criptográfico
Instituto Politécnico Nacional - ESCOM
Introduction to Cryptography
"""

import os
from app import app, db

def create_database():
    """Crear base de datos si no existe"""
    with app.app_context():
        db.create_all()
        print("✅ Base de datos inicializada correctamente")

def main():
    """Función principal"""
    print("🔐 CRYPTO LOGIN SYSTEM - IPN ESCOM")
    print("=" * 50)
    
    # Crear base de datos
    create_database()
    
    # Configurar puerto y host
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    
    print(f"🌐 Servidor iniciando en http://{host}:{port}")
    print("📊 Presiona Ctrl+C para detener")
    print("=" * 50)
    
    # Ejecutar aplicación
    app.run(host=host, port=port, debug=debug)

if __name__ == '__main__':
    main()
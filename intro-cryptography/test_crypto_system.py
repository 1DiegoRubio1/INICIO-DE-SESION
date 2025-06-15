# test_crypto_system.py
"""
Scripts de Prueba para el Sistema de Inicio de Sesión Criptográfico
Instituto Politécnico Nacional - ESCOM
Introduction to Cryptography

Archivo: test_crypto_system.py
Este archivo contiene pruebas automatizadas para validar:
- Funciones criptográficas
- Seguridad de contraseñas
- Generación de tokens
- Validación de emails
- Integridad del sistema
"""

import unittest
import hashlib
import secrets
import time
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import sys
import os

# Agregar el directorio padre al path para importar la aplicación
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Importar clases del sistema principal
try:
    from app import app, db, User, LoginAttempt, CryptoManager, EmailService
except ImportError:
    print("Error: No se puede importar la aplicación principal")
    print("Asegúrate de que app.py esté en el mismo directorio")
    sys.exit(1)

class TestCryptographicFunctions(unittest.TestCase):
    """
    Pruebas para las funciones criptográficas principales
    """
    
    def setUp(self):
        """Configuración inicial para cada prueba"""
        self.test_password = "MiContraseñaSegura123!"
        self.crypto_manager = CryptoManager()
    
    def test_sha256_hash_generation(self):
        """
        Prueba la generación correcta de hash SHA-256
        """
        print("\n🔍 Probando generación de hash SHA-256...")
        
        # Generar hash SHA-256
        client_hash = CryptoManager.generate_client_hash(self.test_password)
        
        # Verificar longitud (64 caracteres hexadecimales)
        self.assertEqual(len(client_hash), 64)
        
        # Verificar que es hexadecimal válido
        try:
            int(client_hash, 16)
            is_hex = True
        except ValueError:
            is_hex = False
        self.assertTrue(is_hex)
        
        # Verificar consistencia (mismo input = mismo output)
        client_hash2 = CryptoManager.generate_client_hash(self.test_password)
        self.assertEqual(client_hash, client_hash2)
        
        # Verificar diferencia con input diferente
        different_hash = CryptoManager.generate_client_hash("contraseña_diferente")
        self.assertNotEqual(client_hash, different_hash)
        
        print(f"   ✅ Hash SHA-256 generado correctamente: {client_hash[:16]}...")
        print(f"   ✅ Longitud: {len(client_hash)} caracteres")
        print(f"   ✅ Formato hexadecimal válido")
        print(f"   ✅ Consistencia verificada")
    
    def test_pbkdf2_hash_generation(self):
        """
        Prueba la generación y verificación de hash PBKDF2
        """
        print("\n🔒 Probando generación de hash PBKDF2...")
        
        # Generar hash del cliente primero
        client_hash = CryptoManager.generate_client_hash(self.test_password)
        
        # Generar hash del servidor
        server_hash = CryptoManager.generate_server_hash(client_hash)
        
        # Verificar formato PBKDF2
        self.assertTrue(server_hash.startswith('pbkdf2:sha256:'))
        
        # Verificar que contiene salt y hash
        parts = server_hash.split('$')
        self.assertEqual(len(parts), 3)  # método:iteraciones$salt$hash
        
        # Verificar verificación de contraseña
        is_valid = CryptoManager.verify_password(client_hash, server_hash)
        self.assertTrue(is_valid)
        
        # Verificar que hash diferente no es válido
        wrong_client_hash = CryptoManager.generate_client_hash("contraseña_incorrecta")
        is_invalid = CryptoManager.verify_password(wrong_client_hash, server_hash)
        self.assertFalse(is_invalid)
        
        # Verificar que cada hash es único (diferentes salts)
        server_hash2 = CryptoManager.generate_server_hash(client_hash)
        self.assertNotEqual(server_hash, server_hash2)
        
        print(f"   ✅ Hash PBKDF2 generado: {server_hash[:30]}...")
        print(f"   ✅ Formato válido con salt único")
        print(f"   ✅ Verificación de contraseña funcional")
        print(f"   ✅ Salts únicos por hash")
    
    def test_secure_token_generation(self):
        """
        Prueba la generación de tokens seguros
        """
        print("\n🎲 Probando generación de tokens seguros...")
        
        # Generar múltiples tokens
        tokens = [CryptoManager.generate_secure_token() for _ in range(100)]
        
        # Verificar longitud estándar
        for token in tokens[:5]:  # Verificar primeros 5
            self.assertEqual(len(token), 43)  # URL-safe base64 de 32 bytes
        
        # Verificar unicidad (muy improbable que sean iguales)
        unique_tokens = set(tokens)
        self.assertEqual(len(unique_tokens), len(tokens))
        
        # Verificar caracteres válidos para URL-safe base64
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')
        for token in tokens[:10]:  # Verificar primeros 10
            token_chars = set(token.rstrip('='))  # Remover padding
            self.assertTrue(token_chars.issubset(valid_chars))
        
        print(f"   ✅ 100 tokens generados, todos únicos")
        print(f"   ✅ Longitud estándar: 43 caracteres")
        print(f"   ✅ Formato URL-safe base64 válido")
        print(f"   ✅ Ejemplo: {tokens[0]}")
    
    def test_token_expiration(self):
        """
        Prueba la función de expiración de tokens
        """
        print("\n⏰ Probando expiración de tokens...")
        
        # Token reciente (no expirado)
        recent_time = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        is_expired = CryptoManager.is_token_expired(recent_time, hours=24)
        self.assertFalse(is_expired)
        
        # Token antiguo (expirado)
        old_time = datetime.datetime.utcnow() - datetime.timedelta(hours=25)
        is_expired = CryptoManager.is_token_expired(old_time, hours=24)
        self.assertTrue(is_expired)
        
        # Token None (siempre expirado)
        is_expired = CryptoManager.is_token_expired(None)
        self.assertTrue(is_expired)
        
        print("   ✅ Tokens recientes no expiran")
        print("   ✅ Tokens antiguos expiran correctamente")
        print("   ✅ Tokens None se consideran expirados")

class TestPasswordStrength(unittest.TestCase):
    """
    Pruebas para validar la fortaleza de contraseñas
    """
    
    def test_password_entropy(self):
        """
        Calcula y valida la entropía de diferentes contraseñas
        """
        print("\n📊 Analizando entropía de contraseñas...")
        
        def calculate_entropy(password):
            """Calcula la entropía aproximada de una contraseña"""
            charset_size = 0
            if any(c.islower() for c in password):
                charset_size += 26  # a-z
            if any(c.isupper() for c in password):
                charset_size += 26  # A-Z
            if any(c.isdigit() for c in password):
                charset_size += 10  # 0-9
            if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
                charset_size += 32  # símbolos comunes
            
            import math
            entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
            return entropy
        
        test_passwords = [
            ("123456", "Muy débil"),
            ("password", "Débil"),
            ("Password1", "Moderada"),
            ("Password123!", "Fuerte"),
            ("MiContraseñaSegura123!", "Muy fuerte")
        ]
        
        for password, expected_strength in test_passwords:
            entropy = calculate_entropy(password)
            print(f"   📊 '{password}' -> Entropía: {entropy:.1f} bits ({expected_strength})")
            
            # Validar que contraseñas fuertes tengan suficiente entropía
            if expected_strength in ["Fuerte", "Muy fuerte"]:
                self.assertGreater(entropy, 50)  # Mínimo 50 bits de entropía

class TestSystemIntegration(unittest.TestCase):
    """
    Pruebas de integración del sistema completo
    """
    
    @classmethod
    def setUpClass(cls):
        """Configuración una sola vez para todas las pruebas"""
        cls.app = app
        cls.app.config['TESTING'] = True
        cls.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        cls.client = cls.app.test_client()
        
        with cls.app.app_context():
            db.create_all()
    
    def setUp(self):
        """Configuración para cada prueba individual"""
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Limpiar base de datos
        db.session.query(LoginAttempt).delete()
        db.session.query(User).delete()
        db.session.commit()
    
    def tearDown(self):
        """Limpieza después de cada prueba"""
        db.session.rollback()
        self.app_context.pop()
    
    def test_user_registration_flow(self):
        """
        Prueba el flujo completo de registro de usuario
        """
        print("\n👤 Probando flujo de registro de usuario...")
        
        # Simular hash del cliente
        password = "MiContraseñaSegura123!"
        client_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Datos de prueba
        test_data = {
            'username': 'usuario_prueba',
            'email': 'prueba@test.com',
            'password_hash': client_hash
        }
        
        # Realizar petición de registro
        response = self.client.post('/register', 
                                  json=test_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        
        # Verificar que el usuario se creó en la base de datos
        user = User.query.filter_by(username='usuario_prueba').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'prueba@test.com')
        self.assertFalse(user.is_verified)  # Debe empezar no verificado
        self.assertIsNotNone(user.verification_token)
        
        print("   ✅ Usuario registrado exitosamente")
        print(f"   ✅ Token de verificación generado: {user.verification_token[:16]}...")
        print("   ✅ Estado inicial: no verificado")
    
    def test_login_flow(self):
        """
        Prueba el flujo de inicio de sesión
        """
        print("\n🔐 Probando flujo de inicio de sesión...")
        
        # Crear usuario de prueba
        password = "MiContraseñaSegura123!"
        client_hash = hashlib.sha256(password.encode()).hexdigest()
        server_hash = generate_password_hash(client_hash)
        
        user = User(
            username='test_login',
            email='login@test.com',
            password_hash=server_hash,
            is_verified=True
        )
        db.session.add(user)
        db.session.commit()
        
        # Intentar login con credenciales correctas
        login_data = {
            'username': 'test_login',
            'password_hash': client_hash
        }
        
        response = self.client.post('/login',
                                  json=login_data,
                                  content_type='application/json')
        
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        
        # Verificar que se registró el intento exitoso
        attempts = LoginAttempt.query.filter_by(user_id=user.id).all()
        self.assertEqual(len(attempts), 1)
        self.assertTrue(attempts[0].success)
        
        print("   ✅ Login exitoso con credenciales correctas")
        print("   ✅ Intento registrado en base de datos")
        
        # Intentar login con credenciales incorrectas
        wrong_hash = hashlib.sha256("contraseña_incorrecta".encode()).hexdigest()
        wrong_data = {
            'username': 'test_login',
            'password_hash': wrong_hash
        }
        
        response = self.client.post('/login',
                                  json=wrong_data,
                                  content_type='application/json')
        
        data = response.get_json()
        self.assertFalse(data['success'])
        
        # Verificar que se registró el intento fallido
        attempts = LoginAttempt.query.filter_by(user_id=user.id).all()
        self.assertEqual(len(attempts), 2)
        self.assertFalse(attempts[1].success)
        
        print("   ✅ Login fallido con credenciales incorrectas")
        print("   ✅ Intento fallido registrado correctamente")

class TestPerformanceBenchmarks(unittest.TestCase):
    """
    Pruebas de rendimiento para operaciones criptográficas
    """
    
    def test_hashing_performance(self):
        """
        Mide el rendimiento de las operaciones de hash
        """
        print("\n⚡ Midiendo rendimiento de operaciones de hash...")
        
        password = "MiContraseñaSegura123!"
        
        # Benchmark SHA-256 (cliente)
        start_time = time.time()
        for _ in range(1000):
            CryptoManager.generate_client_hash(password)
        sha256_time = (time.time() - start_time) / 1000
        
        # Benchmark PBKDF2 (servidor)
        client_hash = CryptoManager.generate_client_hash(password)
        start_time = time.time()
        for _ in range(10):  # Menos iteraciones porque es más lento
            CryptoManager.generate_server_hash(client_hash)
        pbkdf2_time = (time.time() - start_time) / 10
        
        # Benchmark generación de tokens
        start_time = time.time()
        for _ in range(1000):
            CryptoManager.generate_secure_token()
        token_time = (time.time() - start_time) / 1000
        
        print(f"   📊 SHA-256 promedio: {sha256_time*1000:.2f}ms por hash")
        print(f"   📊 PBKDF2 promedio: {pbkdf2_time*1000:.2f}ms por hash")
        print(f"   📊 Token promedio: {token_time*1000:.2f}ms por token")
        
        # Verificar que los tiempos están dentro de rangos aceptables
        self.assertLess(sha256_time, 0.01)  # SHA-256 < 10ms
        self.assertLess(pbkdf2_time, 1.0)   # PBKDF2 < 1 segundo
        self.assertLess(token_time, 0.01)   # Token < 10ms

def run_security_audit():
    """
    Ejecuta una auditoría básica de seguridad del sistema
    """
    print("\n" + "="*70)
    print("🔍 AUDITORÍA DE SEGURIDAD DEL SISTEMA")
    print("="*70)
    
    audit_results = []
    
    # 1. Verificar fortaleza de algoritmos
    print("\n1. Verificando algoritmos criptográficos...")
    
    # SHA-256
    test_hash = CryptoManager.generate_client_hash("test")
    if len(test_hash) == 64:
        audit_results.append("✅ SHA-256: Implementación correcta")
    else:
        audit_results.append("❌ SHA-256: Problema en implementación")
    
    # PBKDF2
    test_pbkdf2 = CryptoManager.generate_server_hash(test_hash)
    if "pbkdf2:sha256:" in test_pbkdf2:
        audit_results.append("✅ PBKDF2: Implementación correcta")
    else:
        audit_results.append("❌ PBKDF2: Problema en implementación")
    
    # 2. Verificar generación de tokens
    print("\n2. Verificando generación de tokens...")
    
    tokens = [CryptoManager.generate_secure_token() for _ in range(100)]
    if len(set(tokens)) == 100:
        audit_results.append("✅ Tokens: Alta entropía confirmada")
    else:
        audit_results.append("❌ Tokens: Posible problema de entropía")
    
    # 3. Verificar configuración de seguridad
    print("\n3. Verificando configuración...")
    
    if app.config.get('SECRET_KEY') != 'default':
        audit_results.append("✅ Secret Key: Configurada correctamente")
    else:
        audit_results.append("⚠️  Secret Key: Usar clave personalizada en producción")
    
    # 4. Resultados finales
    print("\n" + "="*70)
    print("📋 RESULTADOS DE LA AUDITORÍA")
    print("="*70)
    
    for result in audit_results:
        print(f"   {result}")
    
    success_count = sum(1 for r in audit_results if r.startswith("✅"))
    warning_count = sum(1 for r in audit_results if r.startswith("⚠️"))
    error_count = sum(1 for r in audit_results if r.startswith("❌"))
    
    print(f"\n📊 Resumen: {success_count} ✅ | {warning_count} ⚠️  | {error_count} ❌")
    
    if error_count == 0:
        print("\n🎉 Sistema aprobado para uso en desarrollo")
        if warning_count == 0:
            print("🏆 Configuración de seguridad excelente")
    else:
        print("\n🚨 Se encontraron problemas críticos que deben resolverse")

def main():
    """
    Función principal para ejecutar todas las pruebas
    """
    print("🔐 SISTEMA DE PRUEBAS CRIPTOGRÁFICAS")
    print("Instituto Politécnico Nacional - ESCOM")
    print("Introduction to Cryptography")
    print("="*70)
    
    # Ejecutar auditoría de seguridad primero
    run_security_audit()
    
    print("\n\n🧪 EJECUTANDO PRUEBAS UNITARIAS")
    print("="*70)
    
    # Configurar y ejecutar pruebas
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Agregar pruebas
    suite.addTests(loader.loadTestsFromTestCase(TestCryptographicFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestPasswordStrength))
    suite.addTests(loader.loadTestsFromTestCase(TestSystemIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestPerformanceBenchmarks))
    
    # Ejecutar pruebas con output detallado
    runner = unittest.TextTestRunner(verbosity=2, stream=sys.stdout)
    result = runner.run(suite)
    
    # Resumen final
    print("\n" + "="*70)
    print("📊 RESUMEN DE PRUEBAS")
    print("="*70)
    print(f"   Pruebas ejecutadas: {result.testsRun}")
    print(f"   Pruebas exitosas: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"   Fallas: {len(result.failures)}")
    print(f"   Errores: {len(result.errors)}")
    
    if result.wasSuccessful():
        print("\n🎉 ¡TODAS LAS PRUEBAS PASARON EXITOSAMENTE!")
        print("✅ El sistema está listo para demostración")
    else:
        print("\n🚨 Algunas pruebas fallaron")
        print("❌ Revisar la implementación antes de la demostración")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
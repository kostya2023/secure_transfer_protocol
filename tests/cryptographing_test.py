from secure_transfer_protocol.cryptographing import Crypting
import os
import base64

def demo_cryptography():
    print("=== Демонстрация криптографических операций ===")
    
    # Генерация ключей
    if not os.path.exists("private_key.pem"):
        print("Генерация новых ключей...")
        pub_key, priv_key = Crypting.generate_dilithium_keys()
        Crypting.write_keys(priv_key, pub_key)
    
    # Загрузка ключей
    priv_key, pub_key = Crypting.read_keys()
    print(f"Публичный ключ (первые 50 символов): {pub_key[:50]}...")
    
    # Подпись и проверка
    message = "Важное сообщение"
    signature = Crypting.sign_message(priv_key, message)
    is_valid = Crypting.verify_signature(pub_key, message, signature)
    print(f"Проверка подписи: {'успешно' if is_valid else 'не удалась'}")
    
    # Шифрование/дешифрование
    aes_key = base64.b64encode(os.urandom(32)).decode()
    hmac_key = base64.b64encode(os.urandom(32)).decode()
    encrypted = Crypting.crypt(aes_key, "Секретные данные", hmac_key)
    decrypted = Crypting.decrypt(aes_key, encrypted, hmac_key)
    print(f"Дешифрованные данные: {decrypted}")

if __name__ == "__main__":
    demo_cryptography()
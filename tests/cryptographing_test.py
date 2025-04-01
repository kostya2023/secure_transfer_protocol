from secure_transfer_protocol.cryptographing import Crypting, Nonce
import os
import base64
import time

def demo_cryptography():
    print("\n=== Демонстрация криптографических операций ===")
    
    # 1. Тестирование работы с ключами
    print("\n[1/4] Тестирование работы с ключами Dilithium")
    if not os.path.exists("private_key.pem"):
        print("Генерация новых ключей...")
        pub_key, priv_key = Crypting.generate_dilithium_keys()
        Crypting.write_keys(priv_key, pub_key)
    
    priv_key, pub_key = Crypting.read_keys()
    print(f"• Публичный ключ (первые 50 символов): {pub_key[:50]}...")
    print(f"• Приватный ключ (первые 50 символов): {priv_key[:50]}...")
    
    # 2. Тестирование подписи и верификации
    print("\n[2/4] Тестирование подписи сообщений")
    test_messages = [
        "Важное сообщение",
        "Длинное сообщение " * 50,
        "Спецсимволы: !@#$%^&*()"
    ]
    
    for msg in test_messages:
        signature = Crypting.sign_message(priv_key, msg)
        is_valid = Crypting.verify_signature(pub_key, msg, signature)
        print(f"• Сообщение '{msg[:15]}...': проверка {'OK' if is_valid else 'FAIL'}")
        assert is_valid, "Ошибка верификации подписи"
    
    # 3. Тестирование симметричного шифрования
    print("\n[3/4] Тестирование AES-шифрования с HMAC")
    aes_key = base64.b64encode(os.urandom(32)).decode()
    hmac_key = base64.b64encode(os.urandom(32)).decode()
    
    test_data = [
        "Секретные данные",
        "Длинные данные " * 100,
        "Бинарные данные: " + os.urandom(32).decode('latin1')
    ]
    
    for data in test_data:
        encrypted = Crypting.crypt(aes_key, data, hmac_key)
        decrypted = Crypting.decrypt(aes_key, encrypted, hmac_key)
        print(f"• Данные '{data[:15]}...': {'OK' if decrypted == data else 'FAIL'}")
        assert decrypted == data, "Ошибка шифрования/дешифрования"
    
    # 4. Тестирование Nonce
    print("\n[4/4] Тестирование механизма Nonce")
    nonce_manager = Nonce()
    generated_nonces = set()
    
    # Генерация 5 nonce
    for i in range(5):
        n = nonce_manager.generate_nonce()
        generated_nonces.add(n)
        print(f"• Сгенерирован nonce {i+1}: {n[:15]}...")
    
    # Проверка уникальности
    assert len(generated_nonces) == 5, "Обнаружены дубликаты nonce"
    
    # Проверка верификации
    test_nonce = next(iter(generated_nonces))
    print(f"\n• Проверка nonce '{test_nonce[:15]}...':")
    print(f"  - Первая проверка (должна пройти): {nonce_manager.verify_nonce(test_nonce)}")
    print(f"  - Вторая проверка (должна fail): {nonce_manager.verify_nonce(test_nonce)}")
    
    # Проверка очистки (имитация)
    print("\n• Имитация очистки устаревших nonce...")
    nonce_manager._used_nonces.clear()
    print(f"  - Проверка после очистки: {nonce_manager.verify_nonce(test_nonce)}")

def performance_test():
    print("\n=== Тест производительности ===")
    
    # Подготовка
    priv_key, pub_key = Crypting.read_keys()
    aes_key = base64.b64encode(os.urandom(32)).decode()
    hmac_key = base64.b64encode(os.urandom(32)).decode()
    data = "Тестовые данные " * 1000
    nonce_manager = Nonce()
    
    # Тесты
    tests = {
        "Генерация nonce": lambda: nonce_manager.generate_nonce(),
        "Подпись сообщения": lambda: Crypting.sign_message(priv_key, data),
        "Шифрование AES": lambda: Crypting.crypt(aes_key, data, hmac_key),
        "Генерация HMAC": lambda: Crypting.generate_hmac(hmac_key, data)
    }
    
    for name, test_func in tests.items():
        start = time.time()
        for _ in range(10):
            test_func()
        duration = (time.time() - start) / 10
        print(f"• {name}: {duration:.4f} сек/операция")

if __name__ == "__main__":
    demo_cryptography()
    performance_test()
    print("\nВсе тесты успешно пройдены!")
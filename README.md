# Secure Transfer Protocol (`STP`)

## Описание
Библиотека для защищенной передачи данных с многоуровневым шифрованием, реализующая:
- Квантово-безопасную аутентификацию (`Dilithium`)
- Постквантовое шифрование (`Kyber`)
- Двойное `AES-256-CBC` шифрование
- Контроль целостности (`HMAC-SHA512`)

## Ключевые особенности
- **Кросс-платформенность** (`Windows`/`Linux`/`macOS`)
- **Синхронизация времени** через `NTP`
- **Сжатие данных** (`gzip`/`zlib`/`bz2`)
- **Подробное логирование** с цветовой маркировкой
- **Контекстные менеджеры** для автоматического управления соединением

## Быстрый старт

### Установка
```bash
pip install secure-transfer-protocol
```

### Пример использования
```python
from secure_transfer_protocol import Transmission

# Серверная часть
with Transmission(is_server=True, port=12345) as server:
    server.handshake()
    server.send("Секретные данные")
    print(server.recv())

# Клиентская часть
with Transmission(host="127.0.0.1", port=12345) as client:
    client.handshake()
    client.send("Ответные данные")
    print(client.recv())
```

## Документация
### Основные модули:
1. **Transmission** - ядро передачи данных
2. **Crypting** - криптографические операции
3. **Compression** - сжатие данных
4. **STPLogger** - система логирования
5. **Time** - синхронизация времени

[Полная документация](docs/docs.md)

## Требования
- Python 3.12+
- Зависимости:
  ```
    cffi >= 1.17.1
    colorama >= 0.4.6
    cryptography >= 44.0.2
    dilithium_python >= 0.1.0
    ntplib >= 0.4.0
    pycparser >= 2.22
    PythonKyber >= 1.0.1
  ```

## Лицензия
[MIT License](LICENSE)

## Авторы:
 - [kostya2023](https://github.com/kostya2023)
from secure_transfer_protocol.compression import Compression

def demo_compression():
    print("=== Демонстрация сжатия данных ===")
    original_text = "Hello, world! " * 50  # Искусственно увеличиваем объем данных
    
    # Сжатие
    print(f"Исходный размер: {len(original_text)} байт")
    compressed = Compression.compress(original_text, "gzip")
    print(f"Сжатые данные (base64): {compressed[:50]}...")
    
    # Распаковка
    decompressed = Compression.decompress(compressed, "gzip")
    print(f"Данные после распаковки совпадают: {decompressed == original_text}")

if __name__ == "__main__":
    demo_compression()
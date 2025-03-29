from secure_transfer_protocol.time_sync import Time
import time

def demo_time_sync():
    print("=== Демонстрация синхронизации времени ===")
    time_obj = Time()
    
    print(f"Текущее время (UNIX): {time_obj.get_time()}")
    print(f"Форматированное время: {time_obj.get_formatted_time()}")
    
    print("Ждем 2 секунды...")
    time.sleep(2)
    print(f"Время после ожидания: {time_obj.get_formatted_time()}")

if __name__ == "__main__":
    demo_time_sync()
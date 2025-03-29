from secure_transfer_protocol.logger import STPLogger

logger = STPLogger()

def demo_logger():
    print("=== Демонстрация работы логгера ===")
    logger.debug("Это сообщение уровня DEBUG")
    logger.info("Информационное сообщение")
    logger.warning("Предупреждение!")
    logger.error("Ошибка обнаружена")
    logger.critical("КРИТИЧЕСКАЯ ОШИБКА!")

if __name__ == "__main__":
    demo_logger()
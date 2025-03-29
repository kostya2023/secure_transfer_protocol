import logging
import sys
from colorama import init, Fore, Back, Style

init(autoreset=True)

class STPLogger:
    """Кастомный логгер для Secure Transfer Protocol"""
    
    def __init__(self, name="STP_logger"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Форматтер с цветами для консоли
        console_formatter = logging.Formatter(
            f"{Fore.CYAN}%(asctime)s{Style.RESET_ALL} | "
            f"{Fore.MAGENTA}%(name)s{Style.RESET_ALL} | "
            f"{Style.BRIGHT}%(levelname)s{Style.RESET_ALL} | "
            f"%(message)s"
        )

        
        # Обработчик для консоли
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(console_formatter)
        
        # Добавляем обработчики
        self.logger.addHandler(console_handler)
        
        # Уровни логирования с цветами
        self.level_colors = {
            'DEBUG': Fore.WHITE,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.WHITE + Back.RED
        }
    
    def _log(self, level, message):
        color = self.level_colors.get(level, '')
        colored_msg = f"{color}{message}{Style.RESET_ALL}"
        getattr(self.logger, level.lower())(colored_msg)
    
    def debug(self, message):
        self._log('DEBUG', message)
    
    def info(self, message):
        self._log('INFO', message)
    
    def warning(self, message):
        self._log('WARNING', message)
    
    def error(self, message):
        self._log('ERROR', message)
    
    def critical(self, message):
        self._log('CRITICAL', message)
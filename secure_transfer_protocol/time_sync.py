import ntplib
import threading
import time
from secure_transfer_protocol.logger import STPLogger


logger = STPLogger()


class Time:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._init_time_sync()
        return cls._instance

    def _init_time_sync(self):
        logger.info("Initializing time synchronization")
        self._ntp_time_start = time.time()
        self._perf_start = time.perf_counter()
        self._resync_interval = 600
        self._is_running = True
        self._sync_with_ntp()
        thread = threading.Thread(
            target=self._resync_loop,
            daemon=True
        )
        thread.start()
        logger.info("Time synchronization started")

    def _sync_with_ntp(self):
        servers = [
            "time.google.com",
            "pool.ntp.org",
            "time.windows.com",
            "time.apple.com",
            "time.cloudflare.com"
        ]
        client = ntplib.NTPClient()
        for server in servers:
            try:
                logger.debug(f"Attempting to sync with {server}")
                response = client.request(server, timeout=2)
                self._ntp_time_start = response.tx_time
                self._perf_start = time.perf_counter()
                logger.info(f"Successfully synced with {server}")
                return
            except Exception as e:
                logger.warning(f"Failed to sync with {server}: {str(e)}")
        logger.error("All NTP servers failed, using system time fallback")

    def _resync_loop(self):
        while self._is_running:
            time.sleep(self._resync_interval)
            self._sync_with_ntp()

    @staticmethod
    def get_time() -> float:
        inst = Time()
        elapsed = time.perf_counter() - inst._perf_start
        return inst._ntp_time_start + elapsed

    @staticmethod
    def get_formatted_time() -> str:
        ts = Time.get_time()
        formatted = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        micros = int((ts % 1) * 1_000_000)
        return f"{formatted}.{micros:06d}"

    def stop(self):
        self._is_running = False
        logger.info("Time synchronization stopped")


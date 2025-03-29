import gzip
import zlib
import bz2
import base64
from secure_transfer_protocol.logger import STPLogger



logger = STPLogger()

class Compression:
    """Класс для сжатия и распаковки данных."""

    @staticmethod
    def compress(data: str, algorithm: str = "gzip") -> str:
        logger.debug(f"Compressing data with {algorithm}")
        data_bytes = data.encode()
        try:
            if algorithm == "gzip":
                compressed_data = gzip.compress(data_bytes)
            elif algorithm == "zlib":
                compressed_data = zlib.compress(data_bytes)
            elif algorithm == "bz2":
                compressed_data = bz2.compress(data_bytes)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            logger.debug("Data compressed successfully")
            return base64.b64encode(compressed_data).decode()
        except Exception as e:
            logger.error(f"Compression failed: {str(e)}")
            raise Exception(f"Compression error: {str(e)}")

    @staticmethod
    def decompress(data: str, algorithm: str = "gzip") -> str:
        logger.debug(f"Decompressing data with {algorithm}")
        try:
            compressed_data = base64.b64decode(data.encode())
            if algorithm == "gzip":
                decompressed_data = gzip.decompress(compressed_data)
            elif algorithm == "zlib":
                decompressed_data = zlib.decompress(compressed_data)
            elif algorithm == "bz2":
                decompressed_data = bz2.decompress(compressed_data)
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            logger.debug("Data decompressed successfully")
            return decompressed_data.decode()
        except Exception as e:
            logger.error(f"Decompression failed: {str(e)}")
            raise Exception(f"Decompression error: {str(e)}")
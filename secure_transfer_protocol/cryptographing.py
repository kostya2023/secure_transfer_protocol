from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import os
import socket
import time
import secrets
import base64
import hashlib
from typing import Tuple, Optional, Dict
import json
import hmac
import dilithium_python as dilithium
import platform
from secure_transfer_protocol.logger import STPLogger



logger = STPLogger()

class Crypting:
    """Класс для криптографических операций."""
    
    @staticmethod
    def generate_hwid() -> str:
        """Генерирует уникальный HWID кросс-платформенно"""
        try:
            system_info = {
                'node': platform.node(),
                'system': platform.system(),
                'release': platform.release(),
                'hostname': socket.gethostname(),
                'pid': os.getpid(),
                'time': time.time()
            }
            hwid = hashlib.sha256(json.dumps(system_info, sort_keys=True).encode()).hexdigest()
            logger.debug(f"Generated HWID: {hwid}")
            return hwid
        except Exception as e:
            logger.warning(f"HWID generation failed, using random: {str(e)}")
            return hashlib.sha256(secrets.token_bytes(32)).hexdigest()

    @staticmethod
    def create_my_peer_info() -> Dict:
        """Создает и возвращает информацию о текущем узле"""
        logger.info("Creating peer info file")
        try:
            private_key, public_key = Crypting.load_or_generate_keys()
            
            peer_info = {
                "HWID": Crypting.generate_hwid(),
                "public_key_fingerprint": hashlib.sha256(public_key.encode()).hexdigest(),
                "public_key": public_key,
                "created_at": int(time.time()),
                "platform": platform.platform(),
                "hostname": socket.gethostname()
            }
            logger.debug("Peer info created successfully")
            return peer_info
        except Exception as e:
            logger.critical(f"Failed to create peer info: {str(e)}")
            raise Exception(f"Peer info creation failed: {str(e)}")

    @staticmethod
    def save_my_peer_info() -> str:
        """Сохраняет информацию о текущем узле в my_peer.json"""
        filename = "my_peer.json"
        try:
            my_info = Crypting.create_my_peer_info()
            
            with open(filename, "w") as f:
                json.dump(my_info, f, indent=2)
            
            logger.info(f"Peer info saved to {filename}")
            return filename
        except Exception as e:
            logger.critical(f"Failed to save peer info: {str(e)}")
            raise Exception(f"Peer info save failed: {str(e)}")

    @staticmethod
    def load_my_peer_info() -> Dict:
        """Загружает информацию о текущем узле"""
        filename = "my_peer.json"
        try:
            if not os.path.exists(filename):
                logger.warning(f"{filename} not found, creating new")
                my_peer_info = Crypting.create_my_peer_info()
                my_peer_info = json.dumps(my_peer_info)
                with open(filename, "w") as file:
                    file.write(my_peer_info)
                logger.info(f"New {filename} created.")
                return my_peer_info
                
            with open(filename, "r") as f:
                data = json.load(f)
                
            required_fields = ['HWID', 'public_key_fingerprint', 'public_key', 'created_at']
            if not all(field in data for field in required_fields):
                raise ValueError("Invalid peer info format")
                
            logger.debug("Peer info loaded successfully")
            return data
        except Exception as e:
            logger.critical(f"Failed to load peer info: {str(e)}")
            raise Exception(f"Peer info load failed: {str(e)}")

    @staticmethod
    def load_another_peer_info() -> Dict:
        """Загружает информацию о другом узле"""
        filename = "another_peer.json"
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"{filename} not found")
                
            with open(filename, "r") as f:
                data = json.load(f)
                
            required_fields = ['HWID', 'public_key_fingerprint', 'public_key']
            if not all(field in data for field in required_fields):
                raise ValueError("Invalid peer info format")
                
            # Verify fingerprint
            actual_fp = hashlib.sha256(data['public_key'].encode()).hexdigest()
            if actual_fp != data['public_key_fingerprint']:
                raise ValueError("Public key fingerprint mismatch")
                
            logger.info("Peer info verified and loaded")
            return data
        except Exception as e:
            logger.critical(f"Failed to load peer info: {str(e)}")
            raise Exception(f"Peer info load failed: {str(e)}")

    @staticmethod
    def hash(data: str) -> str:
        logger.debug("Hashing data with SHA-256")
        return hashlib.sha256(data.encode()).hexdigest()

    @staticmethod
    def write_keys(private_key: str, public_key: str) -> None:
        try:
            with open("private_key.pem", "w") as f:
                f.write(private_key)
            with open("public_key.pem", "w") as f:
                f.write(public_key)
            logger.info("Cryptographic keys saved successfully")
        except Exception as e:
            logger.critical(f"Failed to save keys: {str(e)}")
            raise Exception(f"Key save failed: {str(e)}")

    @staticmethod
    def read_keys() -> Tuple[str, str]:
        try:
            with open("private_key.pem", "r") as f:
                private_key = f.read()
            with open("public_key.pem", "r") as f:
                public_key = f.read()
            logger.debug("Cryptographic keys loaded successfully")
            return private_key, public_key
        except FileNotFoundError:
            logger.warning("Key files not found")
            raise
        except Exception as e:
            logger.critical(f"Failed to load keys: {str(e)}")
            raise Exception(f"Key load failed: {str(e)}")

    @staticmethod
    def generate_dilithium_keys() -> Tuple[str, str]:
        try:
            public_key, private_key = dilithium.Dilithium5.generate_keypair()
            logger.info("New cryptographic keys generated")
            return public_key, private_key
        except Exception as e:
            logger.critical(f"Key generation failed: {str(e)}")
            raise Exception(f"Key generation failed: {str(e)}")

    @staticmethod
    def load_or_generate_keys() -> Tuple[str, str]:
        try:
            if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
                logger.debug("Loading existing cryptographic keys")
                return Crypting.read_keys()
            else:
                logger.info("Generating new cryptographic keys")
                public_key, private_key = Crypting.generate_dilithium_keys()
                Crypting.write_keys(private_key, public_key)
                return private_key, public_key
        except Exception as e:
            logger.critical(f"Key management failed: {str(e)}")
            raise Exception(f"Key management failed: {str(e)}")

    @staticmethod
    def sign_message(private_key: str, message: str) -> str:
        try:
            signature = dilithium.Dilithium5.sign_message(message, private_key)
            logger.debug("Message signed successfully")
            return signature
        except Exception as e:
            logger.error(f"Signing failed: {str(e)}")
            raise Exception(f"Signing failed: {str(e)}")

    @staticmethod
    def verify_signature(public_key: str, message: str, signature: str) -> bool:
        try:
            is_valid = dilithium.Dilithium5.verify_message(signature, message, public_key)
            if is_valid:
                logger.debug("Signature verified successfully")
            else:
                logger.warning("Signature verification failed")
            return is_valid
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            return False

    @staticmethod
    def generate_hmac(key: str, data: str) -> str:
        try:
            key_bytes = base64.b64decode(key.encode())
            data_bytes = data.encode()
            hmac_digest = hmac.new(key_bytes, data_bytes, hashlib.sha512).digest()
            return base64.b64encode(hmac_digest).decode()
        except Exception as e:
            logger.error(f"HMAC generation failed: {str(e)}")
            raise Exception(f"HMAC generation failed: {str(e)}")

    @staticmethod
    def crypt(key: str, data: str, hmac_key: str) -> str:
        logger.debug("Encrypting data with AES-CBC")
        try:
            iv = secrets.token_bytes(16)
            iv_b64 = base64.b64encode(iv).decode()
            key_bytes = base64.b64decode(key.encode())

            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(data.encode()) + padder.finalize()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode()

            hmac_value = Crypting.generate_hmac(hmac_key, encrypted_data_b64)
            packet = f"{encrypted_data_b64}|{iv_b64}|{hmac_value}"
            packet_b64 = base64.b64encode(packet.encode()).decode()

            logger.debug("Data encrypted successfully")
            return packet_b64
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise Exception(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(key: str, data: str, hmac_key: str) -> Optional[str]:
        logger.debug("Decrypting data with AES-CBC")
        try:
            key_bytes = base64.b64decode(key.encode())
            decoded_data = base64.b64decode(data.encode()).decode()
            encrypted_data_b64, iv_b64, hmac_value = decoded_data.split("|")

            # Verify HMAC
            expected_hmac = Crypting.generate_hmac(hmac_key, encrypted_data_b64)
            if not hmac.compare_digest(hmac_value, expected_hmac):
                logger.error("HMAC verification failed - possible tampering")
                raise ValueError("HMAC verification failed")

            iv = base64.b64decode(iv_b64.encode())
            encrypted_data = base64.b64decode(encrypted_data_b64.encode())
            
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
            data_bytes = unpadder.update(padded_data) + unpadder.finalize()

            logger.debug("Data decrypted successfully")
            return data_bytes.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise Exception(f"Decryption failed: {str(e)}")
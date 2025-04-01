from secure_transfer_protocol.compression import Compression
from secure_transfer_protocol.cryptographing import Crypting, Nonce
from secure_transfer_protocol.logger import STPLogger
from secure_transfer_protocol.time_sync import Time
import base64
import socket
import PythonKyber
import json
from typing import Optional


logger = STPLogger()


class Transmission:
    """Класс для защищенной передачи данных."""
    
    def __init__(self, is_server: bool = False, host: str = "127.0.0.1", port: int = 12345, target_ip: Optional[str] = None):
        self.is_server = is_server
        self.host = host
        self.port = port
        self.target_ip = target_ip  # Ожидаемый IP-адрес для верификации
        self.my_socket = None
        self.another_socket = None
        self.public_key = None
        self.private_key = None
        self.another_public_key = None
        self.key_1_level = None
        self.key_2_level = None
        self.key_level_3 = None
        self.handshake_pass = False
        self.time_sync = None
        self.my_peer_info = None
        self.another_peer_info = None
        self.nonce_manager = Nonce()
        
        role = "server" if is_server else "client"
        logger.info(f"Initializing {role} on {host}:{port}")

    def _get_peer_ip(self) -> str:
        """Возвращает IP-адрес подключенного пира"""
        if self.is_server and self.another_socket:
            return self.another_socket.getpeername()[0]
        elif not self.is_server and self.my_socket:
            return self.my_socket.getpeername()[0]
        return ""

    def init(self):
        try:
            self.my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.private_key, self.public_key = Crypting.load_or_generate_keys()
            self.my_peer_info = Crypting.load_my_peer_info()
            self.another_peer_info = Crypting.load_another_peer_info()
            self.another_public_key = self.another_peer_info['public_key']
            self.time_sync = Time()

            if self.is_server:
                logger.info(f"Binding to {self.host}:{self.port}")
                self.my_socket.bind((self.host, self.port))
                
            logger.info("Initialization completed successfully")
        except Exception as e:
            logger.critical(f"Initialization failed: {str(e)}")
            raise Exception(f"Initialization failed: {str(e)}")

    def handshake(self):
        logger.info("Starting handshake process")
        try:
            if self.is_server:
                self._server_handshake()
            else:
                self._client_handshake()
                
            logger.info("Handshake completed successfully")
            self.handshake_pass = True
        except Exception as e:
            logger.critical(f"Handshake failed: {str(e)}")
            raise Exception(f"Handshake failed: {str(e)}")

    def _server_handshake(self):
        logger.info("Starting server-side handshake")
        self.my_socket.listen(1)
        self.another_socket, addr = self.my_socket.accept()
        logger.info(f"Connection accepted from {addr}")

        # Верификация IP-адреса
        if self.target_ip:
            peer_ip = addr[0]
            if peer_ip != self.target_ip:
                logger.critical(f"IP verification failed! Expected: {self.target_ip}, got: {peer_ip}")
                self.another_socket.close()
                raise ConnectionAbortedError("IP address verification failed")

        # Handshake0 - HWID verification
        logger.debug("Starting HWID verification")
        data = self.another_socket.recv(32768)
        if not data:
            raise Exception("No data received from client")

        message, timeset, hwid, nonce = base64.b64decode(data).decode().split("|")
        if message != "START_HANDSHAKE0":
            raise ValueError("Invalid handshake initiation")

        if not self.nonce_manager.verify_nonce(nonce):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(nonce)

        if hwid != self.another_peer_info['HWID']:
            raise ValueError("HWID verification failed")

        response = f"HANDSHAKE0_OK|{self.time_sync.get_time()}|{self.nonce_manager.generate_nonce()}"
        self.another_socket.sendall(base64.b64encode(response.encode()))
        logger.info("HWID verified successfully")

        # Handshake1 - Key exchange
        handshake_nonce = self.nonce_manager.generate_nonce()
        public_kyber_key, private_kyber_key = PythonKyber.Kyber1024.generate_keypair()
        public_kyber_key_b64 = base64.b64encode(public_kyber_key).decode()
        signature = Crypting.sign_message(self.private_key, public_kyber_key_b64)

        packet = {
            "step": "HANDSHAKE1",
            "public_key": public_kyber_key_b64,
            "signature": signature,
            "timeset": self.time_sync.get_time(),
            "nonce": handshake_nonce
        }
        self.another_socket.sendall(json.dumps(packet).encode())
        logger.debug("Sent handshake1 packet")

        response = json.loads(self.another_socket.recv(32768).decode())
        if not self.nonce_manager.verify_nonce(response.get("nonce", "")):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(response["nonce"])

        if not Crypting.verify_signature(self.another_public_key, response["ciphertext"], response["signature"]):
            raise ValueError("Signature verification failed")

        ciphertext = base64.b64decode(response["ciphertext"])
        self.key_1_level = base64.b64encode(PythonKyber.Kyber1024.decapsulate(private_kyber_key, ciphertext)).decode()
        logger.info("Level 1 key established")

        # Handshake2 - Second key exchange
        handshake_nonce2 = self.nonce_manager.generate_nonce()
        public_kyber_key2, private_kyber_key2 = PythonKyber.Kyber1024.generate_keypair()
        signature2 = Crypting.sign_message(self.private_key, base64.b64encode(public_kyber_key2).decode())

        packet2 = {
            "step": "HANDSHAKE2",
            "public_kyber_key": base64.b64encode(public_kyber_key2).decode(),
            "signature": signature2,
            "timeset": self.time_sync.get_time(),
            "nonce": handshake_nonce2
        }
        self.another_socket.sendall(json.dumps(packet2).encode())
        logger.debug("Sent handshake2 packet")

        response2 = json.loads(self.another_socket.recv(32768).decode())
        if not self.nonce_manager.verify_nonce(response2.get("nonce", "")):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(response2["nonce"])

        if not Crypting.verify_signature(self.another_public_key, response2["ciphertext"], response2["signature"]):
            raise ValueError("Signature verification failed")

        ciphertext2 = base64.b64decode(response2["ciphertext"])
        self.key_2_level = base64.b64encode(PythonKyber.Kyber1024.decapsulate(private_kyber_key2, ciphertext2)).decode()
        logger.info("Level 2 key established")

        # Handshake3 - HMAC key exchange
        handshake_nonce3 = self.nonce_manager.generate_nonce()
        public_kyber_key3, private_kyber_key3 = PythonKyber.Kyber1024.generate_keypair()
        signature3 = Crypting.sign_message(self.private_key, base64.b64encode(public_kyber_key3).decode())

        packet3 = {
            "step": "HANDSHAKE3",
            "public_kyber_key": base64.b64encode(public_kyber_key3).decode(),
            "signature": signature3,
            "timeset": self.time_sync.get_time(),
            "nonce": handshake_nonce3
        }
        self.another_socket.sendall(json.dumps(packet3).encode())
        logger.debug("Sent handshake3 packet")

        response3 = json.loads(self.another_socket.recv(32768).decode())
        if not self.nonce_manager.verify_nonce(response3.get("nonce", "")):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(response3["nonce"])

        if not Crypting.verify_signature(self.another_public_key, response3["ciphertext"], response3["signature"]):
            raise ValueError("Signature verification failed")

        ciphertext3 = base64.b64decode(response3["ciphertext"])
        self.key_level_3 = base64.b64encode(PythonKyber.Kyber1024.decapsulate(private_kyber_key3, ciphertext3)).decode()
        logger.info("Level 3 key established")


    def _client_handshake(self):
        logger.info("Starting client-side handshake")
        self.my_socket.connect((self.host, self.port))

        # Верификация IP-адреса
        if self.target_ip:
            peer_ip = self._get_peer_ip()
            if peer_ip != self.target_ip:
                logger.critical(f"IP verification failed! Expected: {self.target_ip}, got: {peer_ip}")
                self.my_socket.close()
                raise ConnectionAbortedError("IP address verification failed")

        # Handshake0 - HWID verification
        logger.debug("Starting HWID verification")
        start_nonce = self.nonce_manager.generate_nonce()
        start_packet = f"START_HANDSHAKE0|{self.time_sync.get_time()}|{self.my_peer_info['HWID']}|{start_nonce}"
        self.my_socket.sendall(base64.b64encode(start_packet.encode()))

        response = base64.b64decode(self.my_socket.recv(32768)).decode()
        parts = response.split("|")
        if len(parts) < 3:
            raise ValueError("Invalid response format")
            
        response_msg, timeset, nonce = parts[0], parts[1], parts[2]
        if response_msg != "HANDSHAKE0_OK":
            raise ValueError("HWID verification failed")

        if not self.nonce_manager.verify_nonce(nonce):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(nonce)

        logger.info("HWID verified successfully")

        # Handshake1 - Key exchange
        packet1 = json.loads(self.my_socket.recv(32768).decode())
        if not self.nonce_manager.verify_nonce(packet1.get("nonce", "")):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(packet1["nonce"])

        if not Crypting.verify_signature(self.another_public_key, packet1["public_key"], packet1["signature"]):
            raise ValueError("Signature verification failed")

        public_kyber_key = base64.b64decode(packet1["public_key"])
        shared_secret, ciphertext = PythonKyber.Kyber1024.encapsulate(public_kyber_key)
        self.key_1_level = base64.b64encode(shared_secret).decode()
        signature = Crypting.sign_message(self.private_key, base64.b64encode(ciphertext).decode())

        response1 = {
            "step": "HANDSHAKE1",
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "signature": signature,
            "timeset": self.time_sync.get_time(),
            "nonce": self.nonce_manager.generate_nonce()
        }
        self.my_socket.sendall(json.dumps(response1).encode())
        logger.info("Level 1 key established")

        # Handshake2 - Second key exchange
        packet2 = json.loads(self.my_socket.recv(32768).decode())
        if not self.nonce_manager.verify_nonce(packet2.get("nonce", "")):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(packet2["nonce"])

        if not Crypting.verify_signature(self.another_public_key, packet2["public_kyber_key"], packet2["signature"]):
            raise ValueError("Signature verification failed")

        public_kyber_key2 = base64.b64decode(packet2["public_kyber_key"])
        shared_secret2, ciphertext2 = PythonKyber.Kyber1024.encapsulate(public_kyber_key2)
        self.key_2_level = base64.b64encode(shared_secret2).decode()
        signature2 = Crypting.sign_message(self.private_key, base64.b64encode(ciphertext2).decode())

        response2 = {
            "step": "HANDSHAKE2",
            "ciphertext": base64.b64encode(ciphertext2).decode(),
            "signature": signature2,
            "timeset": self.time_sync.get_time(),
            "nonce": self.nonce_manager.generate_nonce()
        }
        self.my_socket.sendall(json.dumps(response2).encode())
        logger.info("Level 2 key established")

        # Handshake3 - HMAC key exchange
        packet3 = json.loads(self.my_socket.recv(32768).decode())
        if not self.nonce_manager.verify_nonce(packet3.get("nonce", "")):
            raise ValueError("Invalid or reused nonce")
        self.nonce_manager.add_nonce(packet3["nonce"])

        if not Crypting.verify_signature(self.another_public_key, packet3["public_kyber_key"], packet3["signature"]):
            raise ValueError("Signature verification failed")

        public_kyber_key3 = base64.b64decode(packet3["public_kyber_key"])
        shared_secret3, ciphertext3 = PythonKyber.Kyber1024.encapsulate(public_kyber_key3)
        self.key_level_3 = base64.b64encode(shared_secret3).decode()
        signature3 = Crypting.sign_message(self.private_key, base64.b64encode(ciphertext3).decode())

        response3 = {
            "step": "HANDSHAKE3",
            "ciphertext": base64.b64encode(ciphertext3).decode(),
            "signature": signature3,
            "timeset": self.time_sync.get_time(),
            "nonce": self.nonce_manager.generate_nonce()
        }
        self.my_socket.sendall(json.dumps(response3).encode())
        logger.info("Level 3 key established")

    def send(self, data: str, compress: bool = True, compress_algorithm: str = "gzip") -> bool:
        if not self.handshake_pass:
            logger.error("Handshake not completed, cannot send data")
            raise Exception("Handshake not completed")

        try:
            logger.debug(f"Preparing to send data (compress={compress}, algorithm={compress_algorithm})")
            
            # Compression
            if compress and len(data) >= 4096:
                logger.debug("Compressing data")
                data = Compression.compress(data, compress_algorithm)
                data = f"{data}|compress/{compress_algorithm}"

            # Double encryption
            logger.debug("Encrypting with level 1 key")
            encrypted1 = Crypting.crypt(self.key_1_level, data, self.key_level_3)
            
            logger.debug("Encrypting with level 2 key")
            encrypted2 = Crypting.crypt(self.key_2_level, encrypted1, self.key_level_3)
            
            # Signing
            logger.debug("Signing data")
            signature = Crypting.sign_message(self.private_key, encrypted2)

            # Create packet
            packet = {
                "step": "SEND",
                "message": encrypted2,
                "signature": signature,
                "timeset": self.time_sync.get_time(),
                "nonce": self.nonce_manager.generate_nonce()  # Добавлен nonce
            }
            packet_json = json.dumps(packet)
            
            # Send size first
            size_msg = f"SEND_DATA|{len(packet_json)}|{self.nonce_manager.generate_nonce()}"  # Добавлен nonce
            logger.debug(f"Sending size packet...")
            (self.another_socket if self.is_server else self.my_socket).sendall(size_msg.encode())
            
            # Wait for ACK
            ack = (self.another_socket if self.is_server else self.my_socket).recv(8192).decode()
            if ack != "OKAY":
                raise ConnectionError("Did not receive ACK")
            
            # Send actual data
            logger.debug("Sending packet")
            (self.another_socket if self.is_server else self.my_socket).sendall(packet_json.encode())
            
            logger.info("Data sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send data: {str(e)}")
            raise Exception(f"Send failed: {str(e)}")

    def close(self):
        logger.info("Closing connection...")
        try:
            if self.handshake_pass:
                # Отправляем сообщение о завершении сеанса
                try:
                    end_packet = {
                        "step": "END_SESSION",
                        "timeset": self.time_sync.get_time(),
                        "nonce": self.nonce_manager.generate_nonce()  # Добавлен nonce
                    }
                    (self.another_socket if self.is_server else self.my_socket).sendall(json.dumps(end_packet).encode())
                    logger.debug("Sent END_SESSION notification")
                except Exception as e:
                    logger.warning(f"Could not send END_SESSION: {str(e)}")

            if self.another_socket:
                self.another_socket.close()
            if self.my_socket:
                self.my_socket.close()
            if self.time_sync:
                self.time_sync.stop()
                
            self.handshake_pass = False
            self.key_1_level = None
            self.key_2_level = None
            self.key_level_3 = None
            
            logger.info("Connection closed successfully")
        except Exception as e:
            logger.error(f"Error closing connection: {str(e)}")
            raise Exception(f"Close failed: {str(e)}")

    def recv(self) -> Optional[str]:
        if not self.handshake_pass:
            logger.error("Handshake not completed, cannot receive data")
            raise Exception("Handshake not completed")

        try:
            logger.debug("Waiting for data...")
            
            # Get size first
            size_info = (self.another_socket if self.is_server else self.my_socket).recv(8192).decode()
            
            # Проверка на сообщение о завершении сеанса
            if size_info == "END_SESSION":
                logger.info("Received END_SESSION, closing connection")
                self.close()
                return None
                
            if "|" not in size_info:
                raise ValueError("Invalid size info format")
                
            parts = size_info.split("|")
            if len(parts) < 2:
                raise ValueError("Invalid size info format")
                
            _, size, nonce = parts[0], parts[1], parts[2] if len(parts) > 2 else ""
            
            if nonce and not self.nonce_manager.verify_nonce(nonce):
                raise ValueError("Invalid or reused nonce")
            if nonce:
                self.nonce_manager.add_nonce(nonce)
            
            logger.debug(f"Receiving packet of size: {size}")
            
            # Send ACK
            (self.another_socket if self.is_server else self.my_socket).sendall(b"OKAY")
            
            # Receive data
            data = (self.another_socket if self.is_server else self.my_socket).recv(int(size)).decode()
            packet = json.loads(data)
            
            # Проверка на сообщение о завершении сеанса
            if packet.get("step") == "END_SESSION":
                if not self.nonce_manager.verify_nonce(packet.get("nonce", "")):
                    raise ValueError("Invalid or reused nonce")
                self.nonce_manager.add_nonce(packet["nonce"])
                
                logger.info("Received END_SESSION packet, closing connection")
                self.close()
                return None
                
            if packet["step"] != "SEND":
                raise ValueError("Invalid packet type")
                
            if not self.nonce_manager.verify_nonce(packet.get("nonce", "")):
                raise ValueError("Invalid or reused nonce")
            self.nonce_manager.add_nonce(packet["nonce"])
                
            if not Crypting.verify_signature(self.another_public_key, packet["message"], packet["signature"]):
                raise ValueError("Signature verification failed")
            
            # Double decryption
            logger.debug("Decrypting with level 2 key")
            decrypted2 = Crypting.decrypt(self.key_2_level, packet["message"], self.key_level_3)
            
            logger.debug("Decrypting with level 1 key")
            decrypted1 = Crypting.decrypt(self.key_1_level, decrypted2, self.key_level_3)
            
            # Decompress if needed
            if "|compress/" in decrypted1:
                data, comp_info = decrypted1.split("|")
                comp_type = comp_info.split("/")[1]
                logger.debug(f"Decompressing with {comp_type}")
                result = Compression.decompress(data, comp_type)
            else:
                result = decrypted1
                
            logger.info("Data received successfully")
            return result
        except Exception as e:
            logger.error(f"Failed to receive data: {str(e)}")
            raise Exception(f"Receive failed: {str(e)}")
        
    def __enter__(self):
        """Поддержка контекстного менеджера"""
        self.init()
        if not self.handshake_pass:
            self.handshake()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Автоматическое закрытие при выходе из контекста"""
        self.close()
        if exc_type is not None:
            logger.error(f"Exception occurred: {str(exc_val)}")
        return False


    def get_connection_info(self) -> dict:
        """Возвращает информацию о соединении"""
        peer_ip = self._get_peer_ip() if self.handshake_pass else None
        return {
            "handshake_completed": self.handshake_pass,
            "peer_ip": peer_ip,
            "peer_hwid": self.another_peer_info["HWID"] if self.another_peer_info else None,
            "keys_established": all(k is not None for k in [self.key_1_level, self.key_2_level, self.key_level_3])
        }
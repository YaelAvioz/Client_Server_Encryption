import socket
import sys
import base64
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class Receiver:
    def __init__(self, port, salt, password):
        self._port = int(port)
        self._salt = str.encode(salt)
        self._password = str.encode(password)

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', self._port))
            s.listen()
            while True:
                (connection, add) = s.accept()
                message = connection.recv(1024)
                self._print_message(self._decode(message))

    def _decode(self, message):
        decrypt = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(decrypt.derive(self._password))
        f = Fernet(key)
        data = f.decrypt(message)
        data = data.decode()
        return data

    @staticmethod
    def _print_message(message):
        print('{} {}'.format(message, datetime.now().strftime("%H:%M:%S")))

if __name__ == '__main__':
    password = sys.argv[1]
    salt = sys.argv[2]
    port = sys.argv[3]
    receiver = Receiver(port, salt, password)
    receiver.run()

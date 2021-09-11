# Yael Avioz, 207237421
import socket
from datetime import datetime


class Receiver:
    HOST = '127.0.0.1'
    PORT = 5000

    def __init__(self, salt, password):
        self._salt = salt
        self._password = password

    def run(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self.PORT))
            s.listen()
            connection, _ = s.accept()
            with connection:
                while True:
                    message = connection.recv(1024)
                    if not message:
                        break
                    self._print_message(self._decode(message))

    def _decode(self, message):
        # TODO: Implement
        return message

    @staticmethod
    def _print_message(message):
        print('{} {}'.format(message, datetime.now().strftime("%H:%M:%S")))


if __name__ == '__main__':
    # TODO: find how to get the input
    salt = input()
    password = input()
    receiver = Receiver(salt, password)
    receiver.run()

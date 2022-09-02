import random
import socket
from time import sleep

from constants import ROUND_TIME_IN_SEC


class Server:
    HOST = '127.0.0.1'

    def __init__(self, port, private_key):
        self._port = port
        self._private_key = private_key
        self._messages = []

    def run(self):
        # TODO: one thread to receive, one to send
        pass

    def receive(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.HOST, self._port))
            s.listen()
            conn, _ = s.accept()
            with conn:
                while True:
                    message = conn.recv(1024)
                    if not message:
                        break
                    self._messages.append(message)

    def send(self):
        while True:
            count = len(self._messages)
            messages = self._messages[:count]
            self._messages = self._messages[count:]
            random.shuffle(messages)
            for message in messages:
                decoded_message, dest_ip, dest_port = self._decode(message)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((dest_ip, dest_port))
                    s.sendall(decoded_message)

            sleep(ROUND_TIME_IN_SEC)

    def _decode(self, message):
        # TODO: decrypt message with private key
        # TODO: remove ip + port
        dest_ip, dest_port = '', 0
        decoded_message = message
        return decoded_message, dest_ip, dest_port


if __name__ == '__main__':
    # TODO: find how to get the input
    port = input()
    private_key = input()
    server = Server(port, private_key)

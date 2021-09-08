# Yael Avioz, 207237421, Bar Shein, 316045285
import socket
from time import sleep

from constants import ROUND_TIME_IN_SEC


class Server:
    def __init__(self, ip, port, public_key):
        self.ip = ip
        self.port = port
        self.public_key = public_key


class Message:
    """
    Implements a sender message fields and methods.
    """

    def __init__(self, message_description):
        message, path, round, password, salt, dest_ip, dest_port = message_description.split()
        self._message = message
        self._path = path.split(',')
        self._round = int(round)
        self._password = password
        self._salt = salt
        self._dest_ip = dest_ip
        self._dest_port = dest_port

    def send(self, servers):
        if self._round > 0:
            self._round -= 1
            return 0

        message = self._generate_message_to_send(self._dest_ip, self._dest_port, self._message, self._password)
        for server_name in self._path[:-1]:
            server = servers[server_name]
            message = self._generate_message_to_send(server.ip, server.port, message, server.public_key)

        dest_server = servers[self._path[-1]]
        encrypted_message = self._encrypt(message, dest_server.public_key)

        self._send(dest_server, message)

        return len(encrypted_message)

    @staticmethod
    def _send(dest_server, message):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dest_server.ip, dest_server.port))
            s.sendall(message)

    def _generate_message_to_send(self, ip, port, data, key):
        return ip + port + self._encrypt(data, key)

    def _encrypt(self, data, key):
        # TODO: implement symmetric encryption
        return data


class Sender:
    """
    Implements the sender behaviour.
    """

    def run(self, x):
        messages = self._get_messages(x)
        servers = self._get_servers()

        while messages:
            for i, message in enumerate(messages):
                sent = message.send(servers)
                if sent:
                    messages.pop(i)

            sleep(ROUND_TIME_IN_SEC)

    @staticmethod
    def _get_messages(x):
        with open('messages{}.txt'.format(x)) as messages_descriptions:
            messages = [Message(message_description) for message_description in messages_descriptions]
        return messages

    def _get_servers(self):
        # TODO: return dictionary of server_name : Server() for each mid server we know
        return {'1': Server('127.0.0.1', 5000, 'fjdisiod')}


if __name__ == '__main__':
    sender = Sender()
    x = input()
    sender.run(x)

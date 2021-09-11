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
        message, path, round_number, password, salt, dest_ip, dest_port = message_description.split()
        self._message = message
        self._path = path.split(',')
        self.round_number = int(round_number)
        self._password = password
        self._salt = salt
        self._dest_ip = dest_ip
        self._dest_port = dest_port

    def encode(self, servers):
        message = self._generate_message_to_send(self._dest_ip, self._dest_port, self._message, self._password)
        for server_name in self._path[:-1]:
            server = servers[server_name]
            message = self._generate_message_to_send(server.ip, server.port, message, server.public_key)

        dest_server = servers[self._path[-1]]
        encrypted_message = self._encrypt(message, dest_server.public_key)

        return encrypted_message

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
                if message.round_number > 0:
                    message.round_number -= 1
                else:
                    self._send(servers, messages.pop(i))

            sleep(ROUND_TIME_IN_SEC)

    @staticmethod
    def _send(servers, encoded_message):
        encoded_message = encoded_message.encode(servers)
        dest_server = servers[-1]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((dest_server.ip, dest_server.port))
            s.sendall(encoded_message)

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
    # TODO: find how to get the input
    x = input()
    sender.run(x)

import base64
import socket
from time import sleep
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding

ROUND_TIME_IN_SEC = 60

class Server:
    def __init__(self, server_detail, server_num):
        ip, port = server_detail.split()
        self.ip = ip
        self.port = int(port)
        self.public_key = self.get_pk_by_server_num(server_num)

    def get_pk_by_server_num(self, number):
        pk_file = open('pk{}.pem'.format(number), mode='r')
        pk = pk_file.read()
        pk_file.close()
        return pk

class Message:
    """
    Implements a sender message fields and methods.
    """
    def __init__(self, message_description):
        message, path, round_number, password, salt, dest_ip, dest_port = message_description.split()
        path = path.split(',')
        path.reverse()
        self._message = str.encode(message)
        self._path = path
        self.round_number = int(round_number)
        self._password = str.encode(password)
        self._salt = str.encode(salt)
        self._dest_ip = dest_ip
        self._dest_port = int(dest_port)

    def encode_msg(self, servers):
        is_first_server = True
        # create msg = ip||port||c (symmetric encryption of data)
        message = self._encrypt_symmetric_msg(self._dest_ip, self._dest_port, self._message,
                                              self._password, self._salt)
        # encrypt the message for each server in path
        for server_name in self._path[:]:
            server = servers[int(server_name)-1]
            if(is_first_server):
                # only encrypt, without concat - l1 = Enc(PK1, msg)
                message = self._encrypt(message, server.public_key)
                is_first_server = False
            else:
                # concat ip and port to message and encrypt
                pre_server = servers[int(server_name)-2]
                message = self._generate_message_to_send(pre_server.ip, pre_server.port, message, server.public_key)
        return message

    def _generate_message_to_send(self, ip, port, message, key):
        ip = socket.inet_aton(ip)
        port = port.to_bytes(2, byteorder='big')
        return self._encrypt(ip + port + message, key)

    def _encrypt(self, data, key):
        public_key = load_pem_public_key(key.encode(), backend=default_backend())
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    # create msg = ip||port||c (symmetric encryption of data)
    def _encrypt_symmetric_msg(self, dest_ip, dest_port, message, password, salt):
        c = self._symmetric_encrypt(message, password, salt)
        dest_ip = socket.inet_aton(dest_ip)
        dest_port = dest_port.to_bytes(2, byteorder='big')
        # concat msg = ip||port||c
        return dest_ip + dest_port + c

    # create c (symmetric encryption of data)
    def _symmetric_encrypt(self, message, password, salt):
        enc = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(enc.derive(password))
        f = Fernet(key)
        encrypted_data = f.encrypt(message)
        return encrypted_data

class Sender:
    """
    Implements the sender behaviour.
    """
    def __init__(self, x):
        self.messages = self._get_messages(x)
        self.servers = self._get_servers()

    def run(self):
        while len(self.messages) != 0:
            i = 0
            while i < len(self.messages):
                if self.messages[i].round_number > 0:
                    self.messages[i].round_number -= 1
                    i += 1
                else:
                    self.send(self.messages.pop(i))
            sleep(ROUND_TIME_IN_SEC)

    def send(self, message):
        encoded_message = message.encode_msg(self.servers)
        dest_server = self.servers[int(message._path[-1])-1]
        # open socket for sending message
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((dest_server.ip,dest_server.port))
        s.send(encoded_message)
        s.close()

    @staticmethod
    def _get_messages(x):
        messages = []
        with open('messages{}.txt'.format(x)) as messages_descriptions:
            for message_description in messages_descriptions:
                messages += [Message(message_description)]
        return messages

    @staticmethod
    def _get_servers():
        line_number = 1
        with open('ips.txt') as servers_details:
            servers = []
            for server_detail in servers_details:
                servers += [Server(server_detail, line_number)]
                line_number += 1
        return servers

if __name__ == '__main__':
    sender = Sender(sys.argv[1])
    sender.run()

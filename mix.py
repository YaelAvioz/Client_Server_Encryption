import random
import socket
import sys
import threading
from time import sleep
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROUND_TIME_IN_SEC = 60

class myThread (threading.Thread):
   def __init__(self, server, option, messages):
      threading.Thread.__init__(self)
      self.server = server
      self.option = option
      self.messages = messages

   def run(self):
       if self.option == "send":
           self.server.send()
       else:
           self.server.send_messages(self.messages)

class Server:
    def __init__(self, server_num):
        self._port = self.get_port_by_server_num(server_num)
        self._private_key = self.get_sk_by_server_num(server_num)
        self._messages = []
        self.socket = None

    def get_sk_by_server_num(self, number):
        sk_file = open('sk{}.pem'.format(number), mode='r')
        sk = sk_file.read()
        sk_file.close()
        return sk

    def get_port_by_server_num(self, number):
        number = int(number)
        servers_info_file = open('ips.txt',  mode='r')
        servers_info_lines = servers_info_file.read()
        servers_info_file.close()
        line_number = 1
        servers_info_lines = servers_info_lines.splitlines()
        for server_line in servers_info_lines:
            if line_number == number:
                line = server_line.split()
                return int(line[1])
            line_number += 1

    def run(self):
        # socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('', self._port))
        self.socket.listen()
        myThread(self, "send", None).start()
        self.receive()

    def receive(self):
        while True:
            (client_conn, client_add) = self.socket.accept()
            message = client_conn.recv(16384)
            self._messages.append(message)

    def send(self):
        while True:
            while len(self._messages) != 0:
                sleep(ROUND_TIME_IN_SEC)
                count = len(self._messages)
                messages = self._messages[:count]
                self._messages = self._messages[count:]
                random.shuffle(messages)
                myThread(self, "send_messages", messages).start()

    def send_messages(self, messages):
        for message in messages:
            decoded_message, dest_ip, dest_port = self._decode(message)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((dest_ip, dest_port))
            s.send(decoded_message)
            s.close()

    def _decode(self, message):
        # decrypt message with private key
        msg = self.decrypt_msg(message)
        # remove ip + port from the decoded message
        dest_ip, dest_port, decoded_message = self.separate_info(msg)
        return decoded_message, dest_ip, dest_port

    def decrypt_msg(self, message):
        private_key = load_pem_private_key(self._private_key.encode(), password=None, backend=default_backend())
        plaintext = private_key.decrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    def separate_info(self, decoded_message):
        # ip is 4 byte
        ip = decoded_message[0:4]
        ip = socket.inet_ntoa(ip)
        # port is 2 byte
        port = decoded_message[4:6]
        port = int.from_bytes(port, byteorder='big')
        # the rest is the message
        msg = decoded_message[6:]
        return ip, port, msg

if __name__ == '__main__':
    server = Server(sys.argv[1])
    server.run()

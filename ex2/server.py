# Yael Avioz, 207237421, Bar Shein, 316045285

import socket


class Server:
    pass


def main():
    HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
    PORT = 65432  # Port to listen on (non-privileged ports are > 1023)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        conn, addr = s.accept()
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                # TODO: save all messages from round togther and send after shuffle
                # TODO: extract next ip, port, message from data and redirect



if __name__ == '__main__':
    main()

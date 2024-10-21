from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

import socket
import threading
import Constants
import ServerSession as Ss


def read_port():
    port = Constants.Constants.DEFAULT_PORT
    try:
        with open(Constants.Constants.PORT_FILE, 'r') as f:
            port = f.read().strip()
    except FileNotFoundError:
        print(f"Error: The file {Constants.Constants.PORT_FILE} was not found. "
              f"Using default port {Constants.Constants.DEFAULT_PORT}.")
    return port


def handle_client(conn, addr, users, lock):
    session = Ss.ServerSession(conn, addr, users, lock)
    session.handle_session()


def main():
    users = {}
    lock = threading.Lock()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((Constants.Constants.HOST, int(read_port())))
            s.listen()
            print(f"Server is listening on {Constants.Constants.HOST}:{read_port()}")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr, users, lock))
                client_thread.start()
    except KeyboardInterrupt:
        print("Server shutting down.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == '__main__':
    main()

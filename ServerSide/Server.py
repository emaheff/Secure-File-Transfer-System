import socket
import threading
import Constants
import ServerSession as Ss


def read_port():
    """
    Reads the server port from a file or returns the default port if the file is not found.

    Returns:
        int: The port number for the server to bind to.
    """
    port = Constants.Constants.DEFAULT_PORT
    try:
        with open(Constants.Constants.PORT_FILE, 'r') as f:
            port = f.read().strip()
    except FileNotFoundError:
        print(f"Error: The file {Constants.Constants.PORT_FILE} was not found. "
              f"Using default port {Constants.Constants.DEFAULT_PORT}.")
    return port


def handle_client(conn, addr, users, lock):
    """
    Handles communication with a single client.

    Args:
        conn (socket): The client connection object.
        addr (tuple): The client address.
        users (dict): Shared dictionary to manage user sessions.
        lock (threading.Lock): Lock for thread-safe access to shared resources.
    """
    try:
        session = Ss.ServerSession(conn, addr, users, lock)
        session.handle_session()
    except Exception as e:
        print(f"Error handling client {addr}: {e}")
    finally:
        # Ensure connection is closed properly in case of error or when done
        conn.close()
        print(f"Connection closed for client {addr}")


def main():
    """
    Main function to start the server and handle incoming connections.
    """
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

import os
import cksum

import Request
import Constants
import Response
import User
import uuid

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad


class ServerSession:
    """
    This class represents a session between the server and a single client, managing
    communication, authentication, file uploads, and encryption.

    Attributes:
        conn (socket): The client connection object.
        addr (tuple): The client address.
        users (dict): Dictionary of users currently connected to the server.
        lock (threading.Lock): Lock for thread-safe access to shared resources.
    """
    def __init__(self, conn, addr, users, lock):
        """
        Initializes a new ServerSession instance.

        Args:
            conn (socket): The client connection object.
            addr (tuple): The client address.
            users (dict): Dictionary to store user sessions.
            lock (threading.Lock): Lock for thread-safe access to shared resources.
        """
        self.conn = conn
        self.addr = addr
        self.users = users
        self.lock = lock

    def handle_session(self):
        """
        Manages the client session, receiving and processing requests until the connection is closed.
        """
        print(f"Connected by {self.addr}")
        while True:
            raw_header_data = self._recv_all(Constants.Request.REQUEST_HEADER_SIZE)
            if raw_header_data is None:
                # Connection closed
                print(f"Connection closed by {self.addr}")
                break
            request_header = Request.RequestHeader(raw_header_data)
            code = request_header.getCode()

            # Handle different request codes
            match code:
                # request code 825
                case Constants.Request.REGISTER_REQUEST:
                    self._handle_register_request(request_header)
                # request code 826
                case Constants.Request.PUBLIC_KEY_SUBMISSION_REQUEST:
                    self._handle_public_key_submission(request_header)
                # request code 827
                case Constants.Request.RECONNECTION_REQUEST:
                    self._handle_reconnection_request(request_header)
                # request code 828
                case Constants.Request.FILE_UPLOAD_REQUEST:
                    self._handle_file_upload_request(request_header)
                # request codes 900, 902
                case Constants.Request.CRC_CONFIRMATION_REQUEST | Constants.Request.CRC_FAILURE_NOTIFICATION_REQUEST:
                    self._handle_crc_confirmation(request_header)
                # request code 901
                case Constants.Request.RETRY_REQUEST:
                    pass

    def _handle_register_request(self, request_header):
        """
        Handles the client registration request.

        Args:
            request_header (Request.RequestHeader): The request header from the client.
        """
        print(Constants.Constants.___ * "-" + '\nReceiving registration request from a client\n' +
              Constants.Constants.___ * "-")

        #  Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        request_payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        print(request_header)
        print(request_payload)

        if not self._register_user(request_payload.getUserName(), request_header):
            self._send_register_failure(request_header)
            return

    def _handle_public_key_submission(self, request_header):
        """
        Handles the client's submission of a public key for encryption.

        Args:
            request_header (Request.RequestHeader): The request header from the client.
        """
        #  Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        request_payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())

        print(Constants.Constants.___ * "-" + '\nReceiving public key submission from the client\n' +
              Constants.Constants.___ * "-")
        print(request_header)
        print(request_payload)
        public_key = request_payload.getPublicKey()

        # Store the public key in the user object
        if not self._store_public_key(request_payload.getUserName(), public_key, request_header):
            self._send_general_failure(request_header)

        # Create and send AES key response
        self._send_encrypted_aes_key(request_payload.getUserName(), public_key, request_header,
                                     Constants.Response.PUBLIC_KEY_RESPONSE)

    def _handle_reconnection_request(self, request_header):
        """
        Handles the client reconnection request.

        Args:
            request_header (Request.RequestHeader): The request header from the client.
        """
        #  Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        request_payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        print(Constants.Constants.___ * "-" + '\nReceiving reconnection request from a client\n' +
              Constants.Constants.___ * "-")
        print(request_header)
        print(request_payload)
        username = request_payload.getUserName()

        # check if the user is registered
        with self.lock:
            if username not in self.users:
                # create _send_reconnection_failure - payload contain just client_id
                self._send_reconnection_failure(request_header)
                return
            else:
                # User found, use user's public key to encrypt the AES key and send it back
                # create _send_encrypted_aes_key - payload contain client_id and symmetric key
                self._send_encrypted_aes_key(username, self.users[username].getPublicKey(), request_header,
                                             Constants.Response.RETRY_CONNECTION_SUCCESS)

    def _handle_file_upload_request(self, request_header):
        """
        Handles the client's file upload request.

        Args:
            request_header (Request.RequestHeader): The request header from the client.
        """
        # Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        # Parse the request payload
        request_payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        username = self._find_username_by_uuid(request_header.getClientId())

        # Verify user and AES key
        user, symmetric_key = self._get_user_and_key(username, request_header)
        if user is None or symmetric_key is None:
            return

        packet_number = request_payload.getPacketNumber()
        total_packets = request_payload.getTotalPackets()
        # Write the file part
        file_name = request_payload.getFileName()
        encrypted_file_part = request_payload.getMessageContent()
        if encrypted_file_part is None:
            print(f'encrypted_file_part is None\npacket number: {packet_number}')
        self._write_file_part(user, file_name, encrypted_file_part)

        if packet_number == 1:
            print(Constants.Constants.___ * "-" + f'\nReceiving file upload request from the client in {total_packets}'
                                                  f' packets\n' + Constants.Constants.___ * "-")
            print(request_header)
            print(request_payload)

        # If this is the last packet, process the file
        if packet_number == total_packets:
            # get thh content size of the entire file after encryption
            encrypted_file_size = os.path.getsize(f"files/{user.getUserName()}/{file_name}.enc")
            self._process_complete_file(user, file_name, symmetric_key, encrypted_file_size, request_header)

    def _handle_crc_confirmation(self, request_header):
        """
        Sends a CRC confirmation response to the client.

        Args:
            request_header (Request.RequestHeader): The request header from the client.
        """
        # send CRC_CONFIRMATION_RESPONSE
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.CONFIRMATION_RESPONSE)
        response_payload = Response.ResponsePayload(request_header.getClientId())
        response = Response.Response(response_header, response_payload)
        self.conn.send(response.toBytes())

    def _recv_all(self, size):
        """
        Receives data from the client until the specified size is reached.

        Args:
            size (int): The number of bytes to receive.

        Returns:
            bytes: The received data, or None if the connection is closed.
        """
        data = b''
        while len(data) < size:
            packet = self.conn.recv(size - len(data))
            if not packet:
                return None  # Connection closed
            data += packet
        return data

    def _send_general_failure(self, request_header):
        """
        Sends a general failure response to the client.

        Args:
            request_header (Request.RequestHeader): The request header from the client.
        """
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.GENERAL_FAILURE)
        self.conn.send(response_header.toBytes())

    def _receive_payload_data(self, request_header):
        """
        Receives the payload data from the client based on the payload size in the header.

        Args:
            request_header (Request.RequestHeader): The request header containing payload size.

        Returns:
            bytes: The received payload data, or None if the connection is closed.
        """
        payload_size = request_header.getPayloadSize()
        payload_data = self._recv_all(payload_size)
        if payload_data is None:
            # Connection closed
            return None
        return payload_data

    def _store_public_key(self, username, public_key, request_header):
        """
        Stores the client's public key for future communication.

        Args:
            username (str): The username associated with the public key.
            public_key (str): The public key to store.
            request_header (Request.RequestHeader): The request header from the client.

        Returns:
            bool: True if successful, False otherwise.
        """
        with self.lock:
            if username not in self.users:
                # User not found, return error
                self._send_general_failure(request_header)
                return False
            else:
                self.users[username].setPublicKey(public_key)
        return True

    def _send_encrypted_aes_key(self, username, public_key, request_header, code):
        """
        Encrypts and sends an AES key to the client using the client's public key.

        Args:
            username (str): The username to whom the AES key is being sent.
            public_key (str): The client's public key for encryption.
            request_header (Request.RequestHeader): The request header from the client.
            code (int): The response code to use in the response.
        """
        try:
            print(Constants.Constants.___ * "-" + '\nCreating and sending encrypted AES key to the client\n' +
                  Constants.Constants.___ * "-")
            # Generate a new AES key
            aes_key = get_random_bytes(Constants.Crypto.AES_KEY_SIZE)  # 32 bytes
            # Encrypt the AES key using the client's public key
            rsa_key = RSA.import_key(public_key)
            # Encrypt the AES key using RSA-OAEP
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
            # Encrypt the AES key
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            self.users[username].setSymmetricKey(aes_key)

            encrypted_aes_key_size = len(encrypted_aes_key)
            response_header = Response.ResponseHeader(request_header.getVersion(), code)

            response_header.setPayloadSize(response_header.getPayloadSize() + encrypted_aes_key_size)

            response_payload = Response.ResponsePayload(request_header.getClientId())
            response_payload.setSymmetricKey(encrypted_aes_key)
            response = Response.Response(response_header, response_payload)
            print(response)
            self.conn.send(response.toBytes())
        except ValueError as e:
            print(f"Error encrypting AES key: {e}")
            self._send_general_failure(request_header)

    def _register_user(self, username, request_header):
        """
        Registers a new user if the username is not already in use.

        Args:
            username (str): The name of the user to register.
            request_header (Request.RequestHeader): The request header containing the client's information.

        Returns:
            bool: True if registration was successful, False if the username already exists.
        """
        with self.lock:
            if username in self.users:
                return False
            else:
                # Register new user
                generated_uuid = uuid.uuid4().hex
                new_user = User.User(username, generated_uuid)
                self.users[username] = new_user
                self._send_register_success(generated_uuid, request_header)
                return True

    def _send_register_failure(self, request_header):
        """
        Sends a registration failure response to the client.

        Args:
            request_header (Request.RequestHeader): The request header containing the client's information.
        """
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.REGISTER_FAILURE)
        print(Constants.Constants.___ * "-" + '\nSending registration failure response to the client\n' +
              Constants.Constants.___ * "-")
        print(response_header)
        self.conn.send(response_header.toBytes())

    def _send_register_success(self, generated_uuid, request_header):
        """
        Sends a registration success response with a generated UUID to the client.

        Args:
            generated_uuid (str): The unique identifier assigned to the user.
            request_header (Request.RequestHeader): The request header containing the client's information.
        """
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.REGISTER_SUCCESS)
        response_payload = Response.ResponsePayload(generated_uuid)
        response = Response.Response(response_header, response_payload)
        print(Constants.Constants.___ * "-" + '\nSending registration success response to the client\n' +
              Constants.Constants.___ * "-")
        print(response)
        self.conn.send(response.toBytes())

    def _send_reconnection_failure(self, request_header):
        """
        Sends a reconnection failure response to the client if reconnection fails.

        Args:
            request_header (Request.RequestHeader): The request header containing the client's information.
        """
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.RETRY_CONNECTION_FAILURE)
        response_payload = Response.ResponsePayload(request_header.getClientId())
        response = Response.Response(response_header, response_payload)
        print(response)
        self.conn.send(response.toBytes())

    def _get_user_and_key(self, username, request_header):
        """
        Retrieves the user and symmetric key based on the username.

        Args:
            username (str): The name of the user to retrieve.
            request_header (Request.RequestHeader): The request header containing the client's information.

        Returns:
            tuple: A tuple containing the user object and the symmetric key, or (None, None) if not found.
        """
        with self.lock:
            if username not in self.users:
                # User not found, send error
                self._send_general_failure(request_header)
                return None, None

            user = self.users[username]
            symmetric_key = user.getSymmetricKey()
            if not symmetric_key:
                # AES key not found, send error
                self._send_general_failure(request_header)
                return None, None

        return user, symmetric_key

    def _write_file_part(self, user, file_name, encrypted_file_part):
        """
        Writes a part of an encrypted file received from the client to the user's file directory.

        Args:
            user (User.User): The user object representing the client.
            file_name (str): The name of the file to write.
            encrypted_file_part (bytes): The encrypted file part to be written.
        """
        # Create user directory if it doesn't exist
        user_directory = f"files/{user.getUserName()}"
        if not os.path.exists(user_directory):
            os.makedirs(user_directory)

        encrypted_file_path = f"{user_directory}/{file_name}.enc"
        # Append the encrypted file part to the file
        with open(encrypted_file_path, 'ab') as f:
            f.write(encrypted_file_part)

    def _process_complete_file(self, user, file_name, symmetric_key, content_size, request_header):
        """
        Processes the complete encrypted file after all parts are received, decrypts it, and calculates the CRC value.

        Args:
            user (User.User): The user object representing the client.
            file_name (str): The name of the encrypted file.
            symmetric_key (bytes): The symmetric key used to decrypt the file.
            content_size (int): The size of the encrypted content.
            request_header (Request.RequestHeader): The request header containing the client's information.
        """
        user_directory = f"files/{user.getUserName()}"
        encrypted_file_path = f"{user_directory}/{file_name}.enc"
        decrypted_file_path = f"{user_directory}/{file_name}"

        print(Constants.Constants.___ * "-" + f'\nDecrypting the encrypted received file - {file_name}\n' +
              Constants.Constants.___ * "-")

        # Decrypt the file
        try:
            decrypted_data = self._decrypt_file(encrypted_file_path, symmetric_key)
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)
        except Exception as e:
            print(f"Decryption failed: {e}")
            self._send_general_failure(request_header)
            return

        print(Constants.Constants.___ * "-" + f'\nCalculating CRC value of the decrypted file - {file_name}\n'
              + Constants.Constants.___ * "-")

        # Calculate the CRC value of the decrypted file
        crc_value = cksum.memcrc(decrypted_data)

        # Send the response
        self._send_file_upload_response(user, file_name, content_size, crc_value, request_header)

        # Clean up the encrypted file
        os.remove(encrypted_file_path)

    def _decrypt_file(self, encrypted_file_path, symmetric_key):
        """
        Decrypts the encrypted file using AES in CBC mode with the provided symmetric key.

        Args:
            encrypted_file_path (str): The path to the encrypted file.
            symmetric_key (bytes): The symmetric key used for decryption.

        Returns:
            bytes: The decrypted file data.

        Raises:
            ValueError: If unpadding the decrypted data fails.
        """
        with open(encrypted_file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()

        # Initialize the AES cipher with CBC mode and a 16-byte IV
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv=bytes(16))
        decrypted_data = cipher.decrypt(encrypted_data)

        # Remove padding using the unpad function
        try:
            decrypted_data = unpad(decrypted_data, AES.block_size)
        except ValueError as e:
            print(f"Error while unpadding: {e}")
            raise

        return decrypted_data

    def _send_file_upload_response(self, user, file_name, content_size, crc_value, request_header):
        """
        Sends a file upload response to the client, including the CRC value of the decrypted file.

        Args:
            user (User.User): The user object representing the client.
            file_name (str): The name of the uploaded file.
            content_size (int): The size of the encrypted content.
            crc_value (int): The CRC value of the decrypted file.
            request_header (Request.RequestHeader): The request header containing the client's information.
        """
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.FILE_UPLOAD_RESPONSE)
        response_payload = Response.ResponsePayload(user.getUuid())
        response_payload.setContentSize(content_size)
        response_payload.setFileName(file_name)
        response_payload.setCrc(crc_value)

        response = Response.Response(response_header, response_payload)
        print(Constants.Constants.___ * "-" + f'\nSending file upload response for the file - {file_name}\n' +
              Constants.Constants.___ * "-")
        print(response)
        data_to_send = response.toBytes()
        self.conn.send(data_to_send)

    def _find_username_by_uuid(self, uuid):
        """
        Finds the username associated with a given UUID.

        Args:
            uuid (str): The UUID to search for.

        Returns:
            str: The username associated with the UUID, or None if not found.
        """
        for username, user in self.users.items():
            if user.getUuid() == uuid:
                return username
        return None

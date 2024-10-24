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
    def __init__(self, conn, addr, users, lock):
        self.conn = conn
        self.addr = addr
        self.users = users
        self.lock = lock

    def handle_session(self):
        print(f"Connected by {self.addr}")
        while True:
            raw_header_data = self._recv_all(Constants.Request.REQUEST_HEADER_SIZE)
            if raw_header_data is None:
                # Connection closed
                print(f"Connection closed by {self.addr}")
                break
            request_header = Request.RequestHeader(raw_header_data)
            code = request_header.getCode()
            print(request_header)

            # Handle different request codes
            match code:
                # request 825
                case Constants.Request.REGISTER_REQUEST:
                    self._handle_register_request(request_header)
                # request 826
                case Constants.Request.PUBLIC_KEY_SUBMISSION_REQUEST:
                    self._handle_public_key_submission(request_header)
                # request 827
                case Constants.Request.RECONNECTION_REQUEST:
                    self._handle_reconnection_request(request_header)
                # request 828
                case Constants.Request.FILE_UPLOAD_REQUEST:
                    self._handle_file_upload_request(request_header)
                # request 900, 902
                case Constants.Request.CRC_CONFIRMATION_REQUEST | Constants.Request.CRC_FAILURE_NOTIFICATION_REQUEST:
                    self._handle_crc_confirmation_or_fatal_error(request_header)
                # request 901
                case Constants.Request.RETRY_REQUEST:
                    pass

    def _handle_register_request(self, request_header):
        #  Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        print(payload)

        if not self._register_user(payload.getUserName(), request_header):
            self._send_register_failure(request_header)
            return

    def _handle_public_key_submission(self, request_header):
        #  Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        print(payload)
        public_key = payload.getPublicKey()

        # Store the public key in the user object
        if not self._store_public_key(payload.getUserName(), public_key, request_header):
            self._send_general_failure(request_header)

        # Create and send AES key response
        self._send_encrypted_aes_key(payload.getUserName(), public_key, request_header,
                                     Constants.Response.PUBLIC_KEY_RESPONSE)

    def _handle_reconnection_request(self, request_header):
        #  Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return
        # check if the user is registered
        request_payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        print(request_payload)
        username = request_payload.getUserName()
        with self.lock:
            if username not in self.users:
                # User not found, return error
                # create _send_reconnection_failure - payload contain just client_id
                self._send_reconnection_failure(request_header)
                return
            else:
                # User found, use user's public key to encrypt the AES key and send it back
                # create _send_encrypted_aes_key - payload contain client_id and symmetric key
                self._send_encrypted_aes_key(username, self.users[username].getPublicKey(), request_header,
                                             Constants.Response.RETRY_CONNECTION_SUCCESS)

    def _handle_file_upload_request(self, request_header):
        # Receive the payload data
        payload_data = self._receive_payload_data(request_header)
        if payload_data is None:
            self._send_general_failure(request_header)
            return

        # Parse the request payload
        payload = Request.RequestPayload(payload_data, request_header.getCode(), request_header.getPayloadSize())
        username = self._find_username_by_uuid(request_header.getClientId())

        # Verify user and AES key
        user, symmetric_key = self._get_user_and_key(username, request_header)
        if user is None or symmetric_key is None:
            return

        packet_number = payload.getPacketNumber()
        total_packets = payload.getTotalPackets()
        # Write the file part
        file_name = payload.getFileName()
        encrypted_file_part = payload.getMessageContent()
        if encrypted_file_part is None:
            print(f'encrypted_file_part is None\npacket number: {packet_number}')
        self._write_file_part(user, file_name, encrypted_file_part)

        # If this is the last packet, process the file
        if packet_number == total_packets:
            # get thh content size of the entire file after encryption
            encrypted_file_size = os.path.getsize(f"files/{user.getUserName()}/{file_name}.enc")
            self._process_complete_file(user, file_name, symmetric_key, encrypted_file_size, request_header)

    def _handle_crc_confirmation_or_fatal_error(self, request_header):
        # send CRC_CONFIRMATION_RESPONSE
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.CONFIRMATION_RESPONSE)
        response_payload = Response.ResponsePayload(request_header.getClientId())
        response = Response.Response(response_header, response_payload)
        self.conn.send(response.toBytes())

    def _recv_all(self, size):
        data = b''
        while len(data) < size:
            packet = self.conn.recv(size - len(data))
            if not packet:
                return None  # Connection closed
            data += packet
        return data

    def _send_general_failure(self, request_header):
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.GENERAL_FAILURE)
        self.conn.send(response_header.headerToBytes())

    def _receive_payload_data(self, request_header):
        payload_size = request_header.getPayloadSize()
        payload_data = self._recv_all(payload_size)
        if payload_data is None:
            # Connection closed
            return None
        return payload_data

    def _store_public_key(self, username, public_key, request_header):
        with self.lock:
            if username not in self.users:
                # User not found, return error
                self._send_general_failure(request_header)
                return False
            else:
                self.users[username].setPublicKey(public_key)
        return True

    def _send_encrypted_aes_key(self, username, public_key, request_header, code):
        try:
            aes_key = get_random_bytes(Constants.Crypto.AES_KEY_SIZE)  # 32 bytes
            rsa_key = RSA.import_key(public_key)
            cipher_rsa = PKCS1_OAEP.new(rsa_key)
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
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.REGISTER_FAILURE)
        self.conn.send(response_header.headerToBytes())

    def _send_register_success(self, generated_uuid, request_header):
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.REGISTER_SUCCESS)
        response_payload = Response.ResponsePayload(generated_uuid)
        response = Response.Response(response_header, response_payload)
        self.conn.send(response.toBytes())

    def _send_reconnection_failure(self, request_header):
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.RETRY_CONNECTION_FAILURE)
        response_payload = Response.ResponsePayload(request_header.getClientId())
        response = Response.Response(response_header, response_payload)
        print(response)
        self.conn.send(response.toBytes())

    def _get_user_and_key(self, username, request_header):
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
        # Create user directory if it doesn't exist
        user_directory = f"files/{user.getUserName()}"
        if not os.path.exists(user_directory):
            os.makedirs(user_directory)

        encrypted_file_path = f"{user_directory}/{file_name}.enc"
        # Append the encrypted file part to the file
        with open(encrypted_file_path, 'ab') as f:
            f.write(encrypted_file_part)

    def _process_complete_file(self, user, file_name, symmetric_key, content_size, request_header):
        user_directory = f"files/{user.getUserName()}"
        encrypted_file_path = f"{user_directory}/{file_name}.enc"
        decrypted_file_path = f"{user_directory}/{file_name}"

        # Decrypt the file
        try:
            decrypted_data = self._decrypt_file(encrypted_file_path, symmetric_key)
            with open(decrypted_file_path, 'wb') as dec_file:
                dec_file.write(decrypted_data)
        except Exception as e:
            print(f"Decryption failed: {e}")
            self._send_general_failure(request_header)
            return

        crc_value = cksum.memcrc(decrypted_data)

        # Send the response
        self._send_file_upload_response(user, file_name, content_size, crc_value, request_header)

        # Clean up the encrypted file
        os.remove(encrypted_file_path)

    def _decrypt_file(self, encrypted_file_path, symmetric_key):
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
        response_header = Response.ResponseHeader(request_header.getVersion(),
                                                  Constants.Response.FILE_UPLOAD_RESPONSE)
        response_payload = Response.ResponsePayload(user.getUuid())
        response_payload.setContentSize(content_size)
        response_payload.setFileName(file_name)
        response_payload.setCrc(crc_value)

        response = Response.Response(response_header, response_payload)
        print(response)
        data_to_send = response.toBytes()
        self.conn.send(data_to_send)

    def _find_username_by_uuid(self, uuid):
        for username, user in self.users.items():
            if user.getUuid() == uuid:
                return username
        return None

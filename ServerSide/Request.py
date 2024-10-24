import struct
import Constants


class RequestHeader:
    """
    This class represents the header of a request, which contains information such as the client ID,
    version, request code, and payload size.

    Attributes:
        client_id (str): The ID of the client (16 bytes, converted to hexadecimal).
        version (int): The version of the protocol being used (1 byte).
        code (int): The operation code of the request (2 bytes).
        payload_size (int): The size of the payload to follow (4 bytes).

    Methods:
        __init__(data): Initializes and unpacks the request header from the given binary data.
        getClientId(): Returns the client ID.
        getVersion(): Returns the version.
        getCode(): Returns the request code.
        getPayloadSize(): Returns the size of the payload.
        __str__(): Returns a formatted string representation of the request header.
    """
    def __init__(self, data):
        """
        Initializes a new instance of the RequestHeader class by unpacking the provided data.

        Args:
            data (bytes): The raw binary data of the header.

        Raises:
            ValueError: If the size of the header is incorrect or any of the fields are invalid.
            struct.error: If unpacking the binary data fails.
        """
        self.client_id = None  # 16 bytes
        self.version = 0  # 1 byte
        self.code = 0  # 2 bytes
        self.payload_size = 0  # 4 bytes

        try:
            if len(data) != Constants.Request.REQUEST_HEADER_SIZE:
                raise ValueError('Invalid request header size')
            self.client_id, self.version, self.code, self.payload_size = struct.unpack('<16sBHI', data)
            self.client_id = self.client_id.hex()
        except struct.error as e:
            print(f'Error: Invalid request header data - {e}')

        # Validate the request header fields that can be validated
        if self.code not in Constants.Request.REQUEST_CODE_LIST:
            raise ValueError('Invalid request code')
        if self.payload_size < 0:
            raise ValueError('Invalid payload size payload size must be greater than 0')

    def getClientId(self):
        """Returns the client ID."""
        return self.client_id

    def getVersion(self):
        """Returns the version of the protocol being used."""
        return self.version

    def getCode(self):
        """Returns the operation code of the request."""
        return self.code

    def getPayloadSize(self):
        """Returns the size of the payload."""
        return self.payload_size

    def __str__(self):
        """
        Returns a formatted string representation of the request header.

        Returns:
            str: A human-readable representation of the request header.
        """
        return (f"\nRequest Header\nClient ID: {self.client_id}\n"
                f"Version: {self.version}\n"
                f"Code: {self.code}\n"
                f"Payload Size: {self.payload_size} bytes\n")


class RequestPayload:
    """
    This class represents the payload of a request, which contains information such as
    the username, public key, file content, and other data based on the request type.

    Attributes:
        user_name (str): The name of the user.
        public_key (bytes): The public key of the user (optional).
        content_size (int): The size of the file or content being transmitted.
        orig_file_size (int): The original size of the file.
        packet_number (int): The number of the current packet in a series.
        total_packets (int): The total number of packets in a series.
        file_name (str): The name of the file being transmitted.
        message_content (bytes): The content of the file or message being transmitted.

    Methods:
        __init__(data, code, payload_size): Initializes and unpacks the request payload from the given binary data.
        getUserName(): Returns the username.
        getPublicKey(): Returns the public key.
        getFileName(): Returns the file name.
        getMessageContent(): Returns the message content.
        getPacketNumber(): Returns the packet number.
        getTotalPackets(): Returns the total packets.
        __str__(): Returns a formatted string representation of the request payload.
    """
    def __init__(self, data, code, payload_size):
        """
        Initializes a new instance of the RequestPayload class by unpacking the provided data.

        Args:
            data (bytes): The raw binary data of the payload.
            code (int): The operation code that determines how to parse the payload.
            payload_size (int): The size of the payload.

        Raises:
            ValueError: If the size of the payload is incorrect or any of the fields are invalid.
            struct.error: If unpacking the binary data fails.
        """
        self.user_name = None
        self.public_key = None
        self.content_size = 0
        self.orig_file_size = 0
        self.packet_number = 0
        self.total_packets = 0
        self.file_name = None
        self.message_content = None

        try:
            if len(data) != payload_size:
                raise ValueError('Invalid payload size')

            match code:
                case Constants.Request.REGISTER_REQUEST | Constants.Request.RECONNECTION_REQUEST:
                    self.user_name = struct.unpack(f'<{Constants.Request.USER_NAME_SIZE}s', data)[0].decode(
                        'utf-8').rstrip('\x00')
                case Constants.Request.PUBLIC_KEY_SUBMISSION_REQUEST:
                    self.user_name, self.public_key = struct.unpack(f'<{Constants.Request.USER_NAME_SIZE}s'
                                                                    f'{Constants.Request.PUBLIC_KEY_SIZE}s', data)
                    self.user_name = self.user_name.decode('utf-8').rstrip('\x00')
                case Constants.Request.FILE_UPLOAD_REQUEST:
                    message_content_size = payload_size - Constants.Request.FILE_NAME_SIZE - \
                            Constants.Request.CONTENT_SIZE_SIZE - Constants.Request.ORIG_FILE_SIZE_SIZE - \
                            Constants.Request.PACKET_NUMBER_SIZE - Constants.Request.TOTAL_PACKETS_SIZE
                    self.content_size, self.orig_file_size, self.packet_number, self.total_packets, self.file_name, \
                        self.message_content = struct.unpack(f'<IIHH{Constants.Request.FILE_NAME_SIZE}s'
                                                             f'{message_content_size}s', data)
                    self.file_name = self.file_name.decode('utf-8').rstrip('\x00')

                    if self.content_size < 0:
                        raise ValueError('Invalid content size. content size must be greater than 0')
                    if self.orig_file_size < 0:
                        raise ValueError('Invalid original file. size original file size must be greater than 0')
                    if self.packet_number < 0:
                        raise ValueError('Invalid packet number. packet number must be greater than 0')
                    if self.total_packets < 0:
                        raise ValueError('Invalid total packets. total packets must be greater than 0')

                case Constants.Request.CRC_CONFIRMATION_REQUEST | Constants.Request.CRC_FAILURE_NOTIFICATION_REQUEST | \
                        Constants.Request.RETRY_REQUEST:
                    self.file_name = struct.unpack(f'<{Constants.Request.FILE_NAME_SIZE}s', data)
                    self.file_name = self.file_name.decode('utf-8').rstrip('\x00')
        except struct.error as e:
            print(f'Error: Invalid request payload data - {e}')

    def getUserName(self):
        """Returns the username."""
        return self.user_name

    def getPublicKey(self):
        """Returns the public key."""
        return self.public_key

    def getFileName(self):
        """Returns the file name."""
        return self.file_name

    def getMessageContent(self):
        """Returns the message content."""
        return self.message_content

    def getPacketNumber(self):
        """Returns the packet number."""
        return self.packet_number

    def getTotalPackets(self):
        """Returns the total number of packets."""
        return self.total_packets

    def __str__(self):
        """
        Returns a formatted string representation of the request payload.

        Returns:
            str: A human-readable representation of the request payload.
        """
        result = 'Request Payload:\n'

        if self.user_name:
            result += f"User Name: {self.user_name}\n"

        if self.public_key:
            result += f"Public Key: {self.public_key.hex()}\n"

        if self.file_name:
            result += f"File Name: {self.file_name}\n"

        if self.message_content:
            result += f"Message Content: {self.message_content.hex()}\n"

        if self.packet_number:
            result += f"Packet Number: {self.packet_number}\n"

        if self.total_packets:
            result += f"Total Packets: {self.total_packets}\n"

        return result

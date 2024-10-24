import struct
import Constants


class ResponseHeader:
    """
    This class represents the header of a response, containing version, response code, and payload size.

    Attributes:
        version (int): The version of the protocol being used.
        code (int): The operation code of the response.
        payload_size (int): The size of the payload to follow.

    Methods:
        headerToBytes(): Converts the header into a byte stream.
        getPayloadSize(): Returns the size of the payload.
        setPayloadSize(payload_size): Sets the size of the payload.
        getCode(): Returns the response code.
        __str__(): Returns a formatted string representation of the response header.
    """
    def __init__(self, version, code):
        """
        Initializes a new instance of the ResponseHeader class.

        Args:
            version (int): The version of the protocol.
            code (int): The operation code of the response.

        Sets the payload size based on the response code.
        """
        self.version = version
        self.code = code
        self.payload_size = 0

        match code:
            case Constants.Response.REGISTER_SUCCESS | Constants.Response.CONFIRMATION_RESPONSE | \
                 Constants.Response.RETRY_CONNECTION_FAILURE | Constants.Response.PUBLIC_KEY_RESPONSE | \
                 Constants.Response.RETRY_CONNECTION_SUCCESS:
                self.payload_size = Constants.Response.CLIENT_ID_SIZE

            case Constants.Response.REGISTER_FAILURE | Constants.Response.GENERAL_FAILURE:
                self.payload_size = 0  # no payload

            case Constants.Response.FILE_UPLOAD_RESPONSE:
                self.payload_size = Constants.Response.CLIENT_ID_SIZE + Constants.Response.CONTENT_SIZE_SIZE + \
                                    Constants.Response.FILE_NAME_SIZE + Constants.Response.CRC_SIZE

    def toBytes(self):
        """
        Converts the response header into a byte stream.

        Returns:
            bytes: The byte stream representing the header.
        """
        return struct.pack('<BHI', self.version, self.code, self.payload_size)

    def getPayloadSize(self):
        """Returns the size of the payload."""
        return self.payload_size

    def setPayloadSize(self, payload_size):
        """
        Sets the size of the payload.

        Args:
            payload_size (int): The new payload size.
        """
        self.payload_size = payload_size

    def getCode(self):
        """Returns the response code."""
        return self.code

    def __str__(self):
        """
        Returns a formatted string representation of the response header.

        Returns:
            str: A human-readable string of the response header.
        """
        return (f"Version: {self.version}\n"
                f"Code: {self.code}\n"
                f"Payload Size: {self.payload_size}")


class ResponsePayload:
    """
    This class represents the payload of a response, containing the client ID, symmetric key, content size,
    file name, and CRC (Cyclic Redundancy Check).

    Attributes:
        client_id (str): The ID of the client.
        symmetric_key (bytes): The symmetric key for encryption (optional).
        content_size (int): The size of the content being transmitted.
        file_name (str): The name of the file being transmitted.
        crc (int): The CRC value used for error-checking.

    Methods:
        setSymmetricKey(symmetric_key): Sets the symmetric key.
        setContentSize(content_size): Sets the content size.
        setFileName(file_name): Sets the file name.
        setCrc(crc): Sets the CRC value.
        payloadToBytes(code): Converts the payload into a byte stream based on the response code.
        getSymmetricKeySizeInBytes(): Returns the size of the symmetric key in bytes.
        __str__(): Returns a formatted string representation of the response payload.
    """
    def __init__(self, client_id):
        """
        Initializes a new instance of the ResponsePayload class.

        Args:
            client_id (str): The ID of the client.
        """
        self.client_id = client_id
        self.symmetric_key = None
        self.content_size = 0
        self.file_name = None
        self.crc = None

    def setSymmetricKey(self, symmetric_key):
        """
        Sets the symmetric key for encryption.

        Args:
            symmetric_key (bytes): The symmetric key to be used.
        """
        self.symmetric_key = symmetric_key

    def setContentSize(self, content_size):
        """
        Sets the content size of the file.

        Args:
            content_size (int): The size of the content being transmitted.
        """
        self.content_size = content_size

    def setFileName(self, file_name):
        """
        Sets the content size of the file.

        Args:
            content_size (int): The size of the content being transmitted.
        """
        self.file_name = file_name

    def setCrc(self, crc):
        """
         Sets the CRC (Cyclic Redundancy Check) value for error-checking.

         Args:
             crc (int): The CRC value.
         """
        self.crc = crc

    def toBytes(self, code):
        """
        Converts the response payload into a byte stream based on the response code.

        Args:
            code (int): The response code that determines how to structure the byte stream.

        Returns:
            bytes: The byte stream representing the payload.
        """

        match code:
            case Constants.Response.REGISTER_SUCCESS | Constants.Response.CONFIRMATION_RESPONSE | \
                 Constants.Response.RETRY_CONNECTION_FAILURE:
                # each 2 characters in the UUID are 1 byte of hexadecimal data
                client_id_byte_stream = bytes.fromhex(self.client_id)
                return struct.pack(f'<{Constants.Response.CLIENT_ID_SIZE}s', client_id_byte_stream)

            case Constants.Response.PUBLIC_KEY_RESPONSE | Constants.Response.RETRY_CONNECTION_SUCCESS:
                client_id_byte_stream = bytes.fromhex(self.client_id)
                return struct.pack(f'<{Constants.Response.CLIENT_ID_SIZE}s{self.getSymmetricKeySizeInBytes()}s',
                                   client_id_byte_stream, self.symmetric_key)

            case Constants.Response.FILE_UPLOAD_RESPONSE:
                client_id_byte_stream = bytes.fromhex(self.client_id)
                file_name_bytes = self.file_name.encode('utf-8')[
                                  :Constants.Response.FILE_NAME_SIZE]
                file_name_bytes = file_name_bytes.ljust(Constants.Response.FILE_NAME_SIZE, b'\x00')

                return struct.pack(f'<{Constants.Response.CLIENT_ID_SIZE}sI{Constants.Response.FILE_NAME_SIZE}sI'
                                   , client_id_byte_stream, self.content_size, file_name_bytes, self.crc)

    def getSymmetricKeySizeInBytes(self):
        """Returns the size of the symmetric key in bytes."""
        return len(self.symmetric_key)

    def __str__(self):
        """
        Returns a formatted string representation of the response payload.

        Returns:
            str: A human-readable string of the response payload.
        """
        result = ''
        if self.client_id:
            result += f"Client ID: {self.client_id}\n"
        if self.symmetric_key:
            result += f"Symmetric Key: {self.symmetric_key}\n"
        if self.content_size != 0:
            result += f"Content Size: {self.content_size}\n"
        if self.file_name:
            result += f"File Name: {self.file_name}\n"
        if self.crc:
            result += f"CRC: {self.crc}\n"
        return result


class Response:
    """
    This class represents a complete response, which includes both a header and a payload.

    Attributes:
        header (ResponseHeader): The response header.
        payload (ResponsePayload): The response payload.

    Methods:
        toBytes(): Converts the entire response into a byte stream.
        __str__(): Returns a formatted string representation of the entire response.
    """
    def __init__(self, header, payload):
        """
        Initializes a new instance of the Response class.

        Args:
            header (ResponseHeader): The header of the response.
            payload (ResponsePayload): The payload of the response.
        """
        self.header = header
        self.payload = payload

    def toBytes(self):
        """
        Converts the entire response (header and payload) into a byte stream.

        Returns:
            bytes: The byte stream representing the entire response.
        """
        return self.header.toBytes() + self.payload.toBytes(self.header.getCode())

    def __str__(self):
        """
        Returns a formatted string representation of the entire response.

        Returns:
            str: A human-readable string of the entire response.
        """
        return (f"Response Header:\n{self.header}\n\n"
                f"Response Payload:\n{self.payload}\n")

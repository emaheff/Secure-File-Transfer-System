import struct
import Constants


class ResponseHeader:
    def __init__(self, version, code):
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

    def headerToBytes(self):
        return struct.pack('<BHI', self.version, self.code, self.payload_size)

    def getPayloadSize(self):
        return self.payload_size

    def setPayloadSize(self, payload_size):
        self.payload_size = payload_size

    def __str__(self):
        return (f"Version: {self.version}\n"
                f"Code: {self.code}\n"
                f"Payload Size: {self.payload_size}")


class ResponsePayload:
    def __init__(self, client_id):
        self.client_id = client_id
        self.symmetric_key = None
        self.content_size = 0
        self.file_name = None
        self.crc = None

    def setSymmetricKey(self, symmetric_key):
        self.symmetric_key = symmetric_key

    def setContentSize(self, content_size):
        self.content_size = content_size

    def setFileName(self, file_name):
        self.file_name = file_name

    def setCrc(self, crc):
        self.crc = crc

    def payloadToBytes(self, code):

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
                file_name_byte_stream = self.file_name.encode('utf-8')
                return struct.pack(f'<{Constants.Response.CLIENT_ID_SIZE}sI{Constants.Response.FILE_NAME_SIZE}sI'
                                   , client_id_byte_stream, self.content_size,
                                   file_name_byte_stream, self.crc)

    def getSymmetricKeySizeInBytes(self):
        return len(self.symmetric_key)

    def __str__(self):
        return (f"Client ID: {self.client_id}\n"
                f"Symmetric Key: {self.symmetric_key}\n"
                f"Content Size: {self.content_size}\n"
                f"File Name: {self.file_name}\n"
                f"CRC: {self.crc}")


class Response:
    def __init__(self, header, payload):
        self.header = header
        self.payload = payload

    def toBytes(self):
        return self.header.headerToBytes() + self.payload.payloadToBytes(self.header.code)

    def __str__(self):
        return (f"Header: {self.header}\n"
                f"Payload: {self.payload}")

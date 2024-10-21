import struct
import Constants


class RequestHeader:
    def __init__(self, data):
        self.client_id = None  # 16 bytes
        self.version = 0  # 1 byte
        self.code = 0  # 2 bytes
        self.payload_size = 0  # 4 bytes

        try:
            self.client_id, self.version, self.code, self.payload_size = struct.unpack('<16sBHI', data)
            self.client_id = self.client_id.hex()
        except struct.error as e:
            print('Error: ', e)

    def getClientId(self):
        return self.client_id

    def getVersion(self):
        return self.version

    def getCode(self):
        return self.code

    def getPayloadSize(self):
        return self.payload_size

    def __str__(self):
        return (f"\nRequest Header\nClient ID: {self.client_id}\n"
                f"Version: {self.version}\n"
                f"Code: {self.code}\n"
                f"Payload Size: {self.payload_size} bytes\n")


class RequestPayload:
    def __init__(self, data, code, payload_size):
        self.user_name = None
        self.public_key = None
        self.content_size = 0
        self.orig_file_size = 0
        self.packet_number = 0
        self.total_packets = 0
        self.file_name = None
        self.message_content = None

        try:
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
                case Constants.Request.CRC_CONFIRMATION_REQUEST | Constants.Request.CRC_FAILURE_NOTIFICATION_REQUEST | \
                        Constants.Request.RETRY_REQUEST:
                    self.file_name = struct.unpack(f'<{Constants.Request.FILE_NAME_SIZE}s', data)
                    self.file_name = self.file_name.decode('utf-8').rstrip('\x00')
        except struct.error as e:
            print('Error: ', e)

    def getUserName(self):
        return self.user_name

    def getPublicKey(self):
        return self.public_key

    def getFileName(self):
        return self.file_name

    def getMessageContent(self):
        return self.message_content

    def getPacketNumber(self):
        return self.packet_number

    def getTotalPackets(self):
        return self.total_packets

    def __str__(self):
        result = []

        if self.user_name:
            result.append(f"User Name: {self.user_name}")

        if self.public_key:
            result.append(f"Public Key: {self.public_key.hex()}")

        if self.file_name:
            result.append(f"File Name: {self.file_name}")

        if self.message_content:
            result.append(f"Message Content: {self.message_content.hex()}")

        if self.packet_number:
            result.append(f"Packet Number: {self.packet_number}")

        if self.total_packets:
            result.append(f"Total Packets: {self.total_packets}")

        if result:
            return "\nRequest Payload\n".join(result)
        else:
            return "Empty Payload"

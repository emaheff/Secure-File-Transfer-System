class Request:
    REGISTER_REQUEST = 825
    PUBLIC_KEY_SUBMISSION_REQUEST = 826
    RECONNECTION_REQUEST = 827
    FILE_UPLOAD_REQUEST = 828
    CRC_CONFIRMATION_REQUEST = 900
    RETRY_REQUEST = 901
    CRC_FAILURE_NOTIFICATION_REQUEST = 902

    USER_NAME_SIZE = 255
    PUBLIC_KEY_SIZE = 160
    PACKET_SIZE = 1024
    FILE_NAME_SIZE = 255
    CONTENT_SIZE_SIZE = 4
    ORIG_FILE_SIZE_SIZE = 4
    PACKET_NUMBER_SIZE = 2
    TOTAL_PACKETS_SIZE = 2

    CLIENT_ID_SIZE = 16
    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4

    REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE

    MESSAGE_CONTENT_SIZE = (PACKET_SIZE - REQUEST_HEADER_SIZE - CONTENT_SIZE_SIZE - ORIG_FILE_SIZE_SIZE
                            - PACKET_NUMBER_SIZE - TOTAL_PACKETS_SIZE - FILE_NAME_SIZE)


class Response:
    REGISTER_SUCCESS = 1600
    REGISTER_FAILURE = 1601
    PUBLIC_KEY_RESPONSE = 1602
    FILE_UPLOAD_RESPONSE = 1603
    CONFIRMATION_RESPONSE = 1604
    RETRY_CONNECTION_SUCCESS = 1605
    RETRY_CONNECTION_FAILURE = 1606
    GENERAL_FAILURE = 1607

    CLIENT_ID_SIZE = 16
    PACKET_SIZE = 1024
    FILE_NAME_SIZE = 255
    CRC_SIZE = 4
    CONTENT_SIZE_SIZE = 4


class Constants:
    PORT_FILE = 'port.info'
    DEFAULT_PORT = '1256'
    HOST = '127.0.0.1'


class Crypto:
    AES_KEY_SIZE = 32

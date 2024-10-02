#ifndef CONSTANTS_H
#define CONSTANTS_H

namespace Constants {
    const int VERSION = 3;
    const int REGISTER_REQUEST = 825;
    const int RECONNECTION_REQUEST = 827;
    const int PUBLIC_KEY_SUBMISSION_REQUEST = 826;
    const int FILE_UPLOAD_REQUEST = 828;
    const int CRC_CONFIRMATION_REQUEST = 900;
    const int CRC_FAILURE_NOTIFICATION_REQUEST = 902;
    const int RETRY_REQUEST = 901;
	const int MAX_USERNAME_LENGTH = 254;

    const std::string TRANSFER_FILE = "transfer.info";
	const int INFO_ADDRESS_AND_PORT_LINE = 1;
	const int INFO_USERNAME_LINE = 2;
	const int INFO_FILE_PATH_LINE = 3;

    const std::string ME_FILE = "me.info";
	const int ME_USERNAME_LINE = 1;
	const int ME_CLIENT_ID_LINE = 2;

	const int PACKET_SIZE = 1024;

	const int HEADER_RESPONSE_SIZE = 7;

	const int VERSION_SIZE = 1;
	const int CODE_SIZE = 2;
	const int PAYLOAD_SIZE_SIZE = 4;

    // Add other constants like fixed field sizes if necessary
}
#endif // CONSTANTS_H

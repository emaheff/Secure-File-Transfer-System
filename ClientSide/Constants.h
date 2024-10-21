#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <string> 

namespace Constants {
    const int VERSION = 3;

	// requesr codes
    const int REGISTER_REQUEST = 825;
	const int PUBLIC_KEY_SUBMISSION_REQUEST = 826;
    const int RECONNECTION_REQUEST = 827;
    const int FILE_UPLOAD_REQUEST = 828;
    const int CRC_CONFIRMATION_REQUEST = 900;
    const int CRC_FAILURE_NOTIFICATION_REQUEST = 902;
    const int RETRY_REQUEST = 901;

	// response codes
	const int REGISTER_SUCCESS = 1600;
	const int REGISTER_FAILURE = 1601;
	const int PUBLIC_KEY_SUBMISSION_SUCCESS = 1602;
	const int FILE_UPLOAD_SUCCESS = 1603;
	const int MESSAGE_SUCCESS = 1604;
	const int RECONNECTION_SUCCESS = 1605;
	const int RECONNECTION_FAILURE = 1606;
	const int GENERAL_ERROR = 1607;

	const int MAX_USERNAME_LENGTH = 254;

    extern std::string TRANSFER_FILE; 
	extern std::string ME_FILE; 

	const int INFO_ADDRESS_AND_PORT_LINE = 1;
	const int INFO_USERNAME_LINE = 2;
	const int INFO_FILE_PATH_LINE = 3;

    
	const int ME_USERNAME_LINE = 1;
	const int ME_CLIENT_ID_LINE = 2;

	const int PACKET_SIZE = 1024;

	
	const int USERNAME_SIZE = 255;
	const int PUBLIC_KEY_SIZE = 160;

	const int CLIENT_ID_SIZE = 16;
	const int VERSION_SIZE = 1;
	const int CODE_SIZE = 2;
	const int PAYLOAD_SIZE_SIZE = 4;
	const int HEADER_RESPONSE_SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE;
	const int REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE;

	const int CONTENT_SIZE_SIZE = 4;
	const int ORIG_FILE_SIZE_SIZE = 4;
	const int PACKET_NUMBER_SIZE = 2;
	const int TOTAL_PACKET_SIZE = 2;
	const int FILE_NAME_SIZE = 255;
	const int Client_ID_SIZE = 16;
	const int CKSUM_SIZE = 4;


    // Add other constants like fixed field sizes if necessary
}
#endif // CONSTANTS_H

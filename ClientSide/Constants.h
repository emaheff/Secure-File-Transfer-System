#ifndef CONSTANTS_H
#define CONSTANTS_H

#include <string> 

/**
 * @namespace Constants
 * @brief A namespace that contains various constants used throughout the client-server communication process.
 *
 * The Constants namespace defines important constants related to message sizes, file paths, and protocol versions
 * that are used in the communication between the client and the server.
 */

namespace Constants {

	constexpr int VERSION = 3;
	constexpr int ___ = 80; // it controls the amount of '-' that separate headers in the console 

	// request fields sizes
	constexpr int CLIENT_ID_SIZE = 16;
	constexpr int VERSION_SIZE = 1;
	constexpr int CODE_SIZE = 2;
	constexpr int PAYLOAD_SIZE_SIZE = 4;
	constexpr int REQUEST_HEADER_SIZE = CLIENT_ID_SIZE + VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE;

	// header response size
	constexpr int HEADER_RESPONSE_SIZE = VERSION_SIZE + CODE_SIZE + PAYLOAD_SIZE_SIZE;


	constexpr int MAX_USERNAME_LENGTH = 254;

	// File paths
    extern std::string TRANSFER_FILE; 
	extern std::string ME_FILE; 
	extern std::string PRIV_FILE; 

	// lines from the files
	constexpr int INFO_ADDRESS_AND_PORT_LINE = 1;
	constexpr int INFO_USERNAME_LINE = 2;
	constexpr int INFO_FILE_PATH_LINE = 3;
	constexpr int ME_USERNAME_LINE = 1;
	constexpr int ME_CLIENT_ID_LINE = 2;

	constexpr int PACKET_SIZE = 1024;

	// request and response payload sizes
	constexpr int USERNAME_SIZE = 255;
	constexpr int PUBLIC_KEY_SIZE = 160;
	constexpr int CONTENT_SIZE_SIZE = 4;
	constexpr int ORIG_FILE_SIZE_SIZE = 4;
	constexpr int PACKET_NUMBER_SIZE = 2;
	constexpr int TOTAL_PACKET_SIZE = 2;
	constexpr int FILE_NAME_SIZE = 255;
	constexpr int Client_ID_SIZE = 16;
	constexpr int CKSUM_SIZE = 4;

}
#endif // CONSTANTS_H

#include "ResponseHeader.h"

/**
 * @brief Constructs a ResponseHeader from the raw byte data received from the server.
 *
 * This constructor parses the raw data into meaningful fields, including the version, operation code,
 * and payload size.
 *
 * @param rawData A vector of chars representing the raw byte data of the response header.
 */
ResponseHeader::ResponseHeader(const std::vector<char>& rawData) {
	version = static_cast<int>(static_cast<uint8_t>(rawData[0]));
	code = static_cast<int>(static_cast<uint8_t>(rawData[1])) | (static_cast<int>(static_cast<uint8_t>(rawData[2])) << 8);
	payloadSize = static_cast<uint8_t>(rawData[3]) |
		(static_cast<uint8_t>(rawData[4]) << 8) |
		(static_cast<uint8_t>(rawData[5]) << 16) |
		(static_cast<uint8_t>(rawData[6]) << 24);
}

/**
 * @brief Returns the operation code of the response.
 *
 * The operation code indicates the type of response received, such as registration success, file received, etc.
 *
 * @return The operation code as an integer.
 */
int ResponseHeader::getCode() const {
	return code;
}

/**
 * @brief Returns the size of the response payload.
 *
 * The payload size represents the number of bytes in the payload portion of the response.
 *
 * @return The payload size in bytes.
 */
int ResponseHeader::getPayloadSize() const {
	return payloadSize;
}

/**
 * @brief Overloads the << operator to print the contents of the response header.
 *
 * Prints the version, operation code, and payload size in a human-readable format.
 * If possible, the operation code is mapped to a human-readable description.
 *
 * @param os The output stream where the response header will be printed.
 * @param header The ResponseHeader object to be printed.
 * @return The output stream after printing the response header.
 */
std::ostream& operator<<(std::ostream& os, const ResponseHeader& header) {
    os << "Response Header:\n";
    os << "Version: " << header.version << "\n";
    os << "Code: " << header.code << " (";

    // Map the code to a human-readable description if possible
    switch (header.code) {
    case ResponseHeader::RegistrationSuccess:
        os << "RegistrationSuccess";
        break;
    case ResponseHeader::RegistrationFailure:
        os << "RegistrationFailure";
        break;
    case ResponseHeader::PublicKeyReceived:
        os << "PublicKeyReceived";
        break;
    case ResponseHeader::FileReceived:
        os << "FileReceived";
        break;
    case ResponseHeader::MessageReceived:
        os << "MessageReceived";
        break;
    case ResponseHeader::ReconnectionSuccess:
        os << "ReconnectionSuccess";
        break;
    case ResponseHeader::ReconnectionFailure:
        os << "ReconnectionFailure";
        break;
    case ResponseHeader::GeneralError:
        os << "GeneralError";
        break;
    default:
        os << "Unknown";
    }

    os << ")\n";
    os << "Payload Size: " << header.payloadSize << " bytes\n";
    return os;
}




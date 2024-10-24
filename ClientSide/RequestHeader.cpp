#include "RequestHeader.h"



/**
 * @brief Constructs a RequestHeader with the specified client ID, version, code, and payload size.
 * @param clientID The client's unique identifier.
 * @param version The version of the protocol used.
 * @param code The operation code indicating the type of request.
 * @param payloadSize The size of the request payload in bytes.
 */
RequestHeader::RequestHeader(std::string clientID, int version, int code, int payloadSize)
	: clientID(clientID), version(version), code(code), payloadSize(payloadSize)
{
}

/**
 * @brief Converts the request header into a byte vector for transmission.
 * This method serializes the clientID, version, code, and payload size into a byte array.
 * @return A vector of chars representing the byte stream of the request header.
 * @throws std::invalid_argument if the client ID is not exactly 32 characters long.
 */
std::vector<char> RequestHeader::toBytes() const {
    std::vector<char> bytes;

    // Convert clientID (32 ASCII characters, each pair representing 1 byte)
    if (clientID.size() != 32) {
        throw std::invalid_argument("clientID must be exactly 32 characters long.");
    }

    for (size_t i = 0; i < clientID.size(); i += 2) {
        // Convert each pair of characters (hex) to a single byte
        std::string byteStr = clientID.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
        bytes.push_back(static_cast<char>(byte));
    }

    // Convert version (1 byte)
    bytes.push_back(static_cast<char>(version));

    // Convert code (2 bytes, little-endian)
    bytes.push_back(static_cast<char>(code & 0xFF));        // Lower byte
    bytes.push_back(static_cast<char>((code >> 8) & 0xFF)); // Higher byte

    // Convert payloadSize (4 bytes, little-endian)
    bytes.push_back(static_cast<char>(payloadSize & 0xFF));         // Byte 1
    bytes.push_back(static_cast<char>((payloadSize >> 8) & 0xFF));  // Byte 2
    bytes.push_back(static_cast<char>((payloadSize >> 16) & 0xFF)); // Byte 3
    bytes.push_back(static_cast<char>((payloadSize >> 24) & 0xFF)); // Byte 4

    return bytes;
}

/**
 * @brief Returns the total size of the request header.
 * @return The size of the request header in bytes.
 */
int RequestHeader::size() const {
	return Constants::CLIENT_ID_SIZE + Constants::VERSION_SIZE + Constants::CODE_SIZE + Constants::PAYLOAD_SIZE_SIZE;
}

/**
 * @brief Overloads the << operator to print the request header's contents.
 * @param os The output stream.
 * @param header The request header to be printed.
 * @return The output stream after printing the request header.
 */
std::ostream& operator<<(std::ostream& os, const RequestHeader& header) {
    os << "Client ID: " << header.clientID << "\n";
    os << "Version: " << header.version << "\n";
    os << "Code: " << header.code << "\n";
    os << "Payload Size: " << header.payloadSize << " bytes\n";
    return os;
}

/**
 * @brief Returns the operation code of the request.
 * @return The operation code (int) representing the type of request.
 */
int RequestHeader::getCode() const {
	return code;
}


#include "RequestHeader.h"

#include <sstream>
#include <iomanip>
#include <stdexcept>

RequestHeader::RequestHeader(std::string clientID, int version, int code, int payloadSize)
	: clientID(clientID), version(version), code(code), payloadSize(payloadSize)
{
}

const int RequestHeader::VERSION = 3;

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

int RequestHeader::size() const {
	return 16 + 1 + 2 + 4; // clientID + version + code + payloadSize
}

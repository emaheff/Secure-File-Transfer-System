#include "ResponseHeader.h"
#include "Constants.h"

ResponseHeader::ResponseHeader(std::vector<char> rawData) {
	version = static_cast<int>(static_cast<uint8_t>(rawData[0]));
	code = static_cast<int>(static_cast<uint8_t>(rawData[1])) | (static_cast<int>(static_cast<uint8_t>(rawData[2])) << 8);
	payloadSize = static_cast<uint8_t>(rawData[3]) |
		(static_cast<uint8_t>(rawData[4]) << 8) |
		(static_cast<uint8_t>(rawData[5]) << 16) |
		(static_cast<uint8_t>(rawData[6]) << 24);
}
int ResponseHeader::getCode() const {
	return code;
}
int ResponseHeader::getPayloadSize() const {
	return payloadSize;
}

std::string ResponseHeader::toString() const {
    std::ostringstream oss;
    oss << "Response Header:\n";
    oss << "Version: " << version << "\n";
    oss << "Code: " << code << " (";

    // Map the code to a human-readable description if possible
    switch (code) {
    case RegistrationSuccess:
        oss << "RegistrationSuccess";
        break;
    case RegistrationFailure:
        oss << "RegistrationFailure";
        break;
    case PublicKeyReceived:
        oss << "PublicKeyReceived";
        break;
    case FileReceived:
        oss << "FileReceived";
        break;
    case MessageReceived:
        oss << "MessageReceived";
        break;
    case ReconnectionSuccess:
        oss << "ReconnectionSuccess";
        break;
    case ReconnectionFailure:
        oss << "ReconnectionFailure";
        break;
    case GeneralError:
        oss << "GeneralError";
        break;
    default:
        oss << "Unknown";
    }

    oss << ")\n";
    oss << "Payload Size: " << payloadSize << " bytes\n";
    return oss.str();
}




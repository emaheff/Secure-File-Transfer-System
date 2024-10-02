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


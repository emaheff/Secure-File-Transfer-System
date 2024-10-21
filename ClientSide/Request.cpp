#include "Request.h"



Request::Request(RequestHeader header, RequestPayload payload) : header(header), payload(payload) {}

std::vector<char> Request::toBytes() const {
	std::vector<char> bytes;

	// Convert the header to bytes and append them to the vector
	std::vector<char> headerBytes = header.toBytes();
	bytes.insert(bytes.end(), headerBytes.begin(), headerBytes.end());

	// Append the payload to the vector
	std::vector<char> payloadBytes = payload.getFlattenedPayload();
	bytes.insert(bytes.end(), payloadBytes.begin(), payloadBytes.end());

	return bytes;
}

int Request::size() const {
	return header.size() + payload.size();
}

std::string Request::toString() const {
	std::ostringstream oss;
	oss << "Request Header:\n" << header.toString() << "\n";
	oss << "Request Payload:\n" << payload.toString() << "\n";
	return oss.str();
}



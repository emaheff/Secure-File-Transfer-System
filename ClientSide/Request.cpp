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



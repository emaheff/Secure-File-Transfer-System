#include "Request.h"


/**
 * @brief Constructs a Request object with the provided header and payload.
 * @param header The RequestHeader object that contains metadata about the request.
 * @param payload The RequestPayload object that contains the actual data for the request.
 */
Request::Request(const RequestHeader& header, const RequestPayload& payload) : header(header), payload(payload) {}

/**
 * @brief Converts the request into a byte vector for transmission over the network.
 *
 * This method serializes the header and payload into a single byte vector that can be sent over
 * a network connection to the server.
 * @return A vector of chars representing the byte stream of the request.
 */
std::vector<char> Request::toBytes() {
	std::vector<char> bytes;

	// Convert the header to bytes and append to the vector
	std::vector<char> headerBytes = header.toBytes();
	bytes.insert(bytes.end(), headerBytes.begin(), headerBytes.end());

	// Append the payload to the vector
	std::vector<char> payloadBytes = payload.toBytes(header.getCode());
	bytes.insert(bytes.end(), payloadBytes.begin(), payloadBytes.end());

	return bytes;
}

/**
 * @brief Calculates the total size of the request.
 *
 * This method returns the combined size of the request header and the payload.
 * @return The total size of the request in bytes.
 */
int Request::size() {
	return header.size() + payload.size();
}

/**
 * @brief Overloads the << operator to print the request's contents.
 * @param os The output stream.
 * @param request The request to be printed.
 * @return The output stream after printing the request.
 */
std::ostream& operator<<(std::ostream& os, const Request& request) {
	os << "Request Header:\n" << request.header;
	os << "Request Payload:\n" << request.payload;
	return os;
}

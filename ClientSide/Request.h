#ifndef REQUEST
#define REQUEST

#include "RequestHeader.h"
#include "RequestPayload.h"
#include <iostream>

/**
 * @class Request
 * @brief Represents a request message that is sent to the server.
 *
 * The Request class encapsulates the header and payload for a client request. It provides methods for
 * serializing the request into a byte stream and calculating the size of the request.
 */
class Request {
public:
	/**
	 * @brief Constructs a Request object with the provided header and payload.
	 * @param header The RequestHeader object that contains metadata about the request.
	 * @param payload The RequestPayload object that contains the actual data for the request.
	 */
	Request(const RequestHeader& header, const RequestPayload& payload);

	/**
	 * @brief Converts the request into a byte vector for transmission over the network.
	 *
	 * This method serializes the header and payload into a single byte vector that can be sent over
	 * a network connection to the server.
	 * @return A vector of chars representing the byte stream of the request.
	 */
	std::vector<char> toBytes();

	/**
	 * @brief Calculates the total size of the request.
	 *
	 * This method returns the combined size of the request header and the payload.
	 * @return The total size of the request in bytes.
	 */
	int size();

	/**
	 * @brief Overloads the << operator to print the request's contents.
	 * @param os The output stream.
	 * @param request The request to be printed.
	 * @return The output stream after printing the request.
	 */
	friend std::ostream& operator<<(std::ostream& os, const Request& request);

private:
	RequestHeader header; ///< The header of the request, containing metadata.
	RequestPayload payload; ///< The payload of the request, containing the data.
};

#endif // !REQUEST

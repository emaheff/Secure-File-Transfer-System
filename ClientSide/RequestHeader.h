#ifndef REQUEST_HEADER
#define REQUEST_HEADER

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include "Constants.h"

/**
 * @class RequestHeader
 * @brief Represents the header of a request sent to the server.
 *
 * The RequestHeader class contains metadata required for a request, including the client ID, protocol version,
 * operation code, and the payload size. It provides methods to convert the header into a byte stream for transmission
 * and to get the size and code of the request.
 */
class RequestHeader
{
public:
    /**
     * @brief Constructs a RequestHeader with the specified client ID, version, code, and payload size.
     * @param clientID The client's unique identifier.
     * @param version The version of the protocol used.
     * @param code The operation code indicating the type of request.
     * @param payloadSize The size of the request payload in bytes.
     */
	RequestHeader(std::string clientID, int version, int code, int payloadSize);

    /**
     * @brief Converts the request header into a byte vector for transmission.
     * This method serializes the header fields into a byte array.
     * @return A vector of chars representing the byte stream of the request header.
     */
	std::vector<char> toBytes() const;

    /**
     * @brief Returns the total size of the request header.
     * @return The size of the request header in bytes.
     */
	int size() const;

    /**
     * @brief Returns the operation code of the request.
     * @return The operation code (int) representing the type of request.
     */
    int getCode() const;


    /**
     * @brief Overloads the << operator to print the request header's contents.
     * @param os The output stream.
     * @param header The request header to be printed.
     * @return The output stream after printing the request header.
     */
    friend std::ostream& operator<<(std::ostream& os, const RequestHeader& header);

    /**
     * @brief Enumeration of operation codes representing various types of requests.
     */
    enum Code {
        RegistrationCode = 825,
        PublicKeyCode = 826,
        ReconnectingCode = 827,
        SendFileCode = 828,
        ValidCRC = 900,
        NotValidCRC = 901,
        NotValidCRC4th = 902
    };

private:
	std::string clientID;  ///< The client's unique identifier.
	int version;           ///< The version of the communication protocol.
    int code;              ///< The operation code of the request.
    int payloadSize;       ///< The size of the request payload.
};
#endif // !REQUESTHEADER

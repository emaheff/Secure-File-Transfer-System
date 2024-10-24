#ifndef RESPONSE_HEADER
#define RESPONSE_HEADER

#include <vector>
#include "ResponsePayload.h"

/**
 * @class ResponseHeader
 * @brief Represents the header of a response received from the server.
 *
 * The ResponseHeader class is responsible for parsing and storing metadata from the server's response,
 * including the version, operation code, and payload size.
 */
class ResponseHeader
{
public:
    /**
     * @brief Constructs a ResponseHeader from the raw byte data received from the server.
     *
     * This constructor parses the raw data into meaningful fields, including the version, operation code,
     * and payload size.
     *
     * @param rawData A vector of chars representing the raw byte data of the response header.
     */
	ResponseHeader(const std::vector<char>& rawData);

    /**
     * @brief Returns the operation code of the response.
     *
     * The operation code indicates the type of response received, such as registration success, file received, etc.
     *
     * @return The operation code as an integer.
     */
	int getCode() const;

    /**
     * @brief Returns the size of the response payload.
     *
     * The payload size represents the number of bytes in the payload portion of the response.
     *
     * @return The payload size in bytes.
     */
	int getPayloadSize() const;

    /**
     * @brief Overloads the << operator to print the contents of the response header.
     *
     * Prints the version, operation code, and payload size in a human-readable format.
     *
     * @param os The output stream where the response header will be printed.
     * @param header The ResponseHeader object to be printed.
     * @return The output stream after printing the response header.
     */
    friend std::ostream& operator<<(std::ostream& os, const ResponseHeader& header);

    /**
     * @brief Enumeration of operation codes representing various types of responses from the server.
     */
    enum Code {
        RegistrationSuccess = 1600,
        RegistrationFailure = 1601,
        PublicKeyReceived = 1602,
        FileReceived = 1603,
        MessageReceived = 1604,
        ReconnectionSuccess = 1605,
        ReconnectionFailure = 1606,
        GeneralError = 1607
    };

private:
    int version;      ///< The version of the communication protocol used.
    int code;         ///< The operation code indicating the type of response.
    int payloadSize;  ///< The size of the response payload in bytes.
};
#endif // !RESPONSE_HEADER

#ifndef RESPONSEPAYLOAD_H
#define RESPONSEPAYLOAD_H

#include <string>
#include <vector>
#include <variant>
#include <sstream>
#include <stdexcept>
#include <iomanip>

#include "Constants.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "ResponseHeader.h"


/**
 * @class ResponsePayload
 * @brief Represents the payload of a response received from the server.
 *
 * The ResponsePayload class is responsible for parsing the payload data of a server's response. It stores the
 * attributes of the payload in a vector of name-value pairs and provides methods for accessing these fields.
 */
class ResponsePayload {
public:
    /**
     * @brief Constructs a ResponsePayload object by parsing the provided header and payload data.
     *
     * This constructor processes the response payload according to the operation code from the header.
     * It extracts fields such as client ID, file name, and content size depending on the code.
     *
	 * @param code The operation code associated with this payload.
     * @param payloadData The raw byte data of the payload.
     */
    ResponsePayload(int code, const std::vector<char>& payloadData);

    /**
     * @brief Overloads the << operator to print the contents of the payload.
     *
     * This method prints all the attributes stored in the payload, including fields like client ID, file name, etc.
     * @param os The output stream to print to.
     * @param payload The ResponsePayload object to print.
     * @return The output stream after printing the payload.
     */
    friend std::ostream& operator<<(std::ostream& os, const ResponsePayload& payload);

    /**
     * @brief Retrieves the value of a specific field in the payload by its name.
     *
     * This method searches through the payload's attributes for the specified field and returns its value.
     * The value can be an int, unsigned long, or string.
     *
     * @param fieldName The name of the field to retrieve.
     * @return A std::variant containing the field's value.
     * @throws std::invalid_argument if the field is not found.
     */
    std::variant<int, unsigned long, std::string> getField(const std::string& fieldName) const;


private:
    // Attributes: vector of pairs where the first is field name and the second is value (int, unsigned long, or string).
    std::vector<std::pair<std::string, std::variant<int, unsigned long, std::string>>> attributes;

    /**
     * @brief Reads an integer from the provided data at the specified offset.
     *
     * This method reads a specified number of bytes from the data vector starting at the given offset, and
     * interprets it as an integer in little-endian format.
     *
     * @param data The data vector to read from.
     * @param offset The starting position in the data vector.
     * @param byteCount The number of bytes to read.
     * @return The integer value read from the data.
     * @throws std::out_of_range if there are not enough bytes to read.
     */
    int readNumber(const std::vector<char>& data, size_t offset, size_t byteCount) const;

    /**
     * @brief Reads a string from the provided data at the specified offset.
     *
     * This method reads a specified number of bytes from the data vector and interprets it as a string.
     *
     * @param data The data vector to read from.
     * @param offset The starting position in the data vector.
     * @param length The number of bytes to read as a string.
     * @return The string read from the data.
     * @throws std::out_of_range if there are not enough bytes to read.
     */
    std::string readString(const std::vector<char>& data, size_t offset, size_t length) const;

    /**
     * @brief Converts a vector of bytes to a hexadecimal string.
     *
     * This method takes a vector of bytes and converts each byte into its corresponding hexadecimal representation.
     *
     * @param buffer The vector of bytes to convert.
     * @return The hexadecimal string representation of the byte vector.
     */
    std::string hexify(const std::vector<char>& buffer);
};
#endif // RESPONSEPAYLOAD_H

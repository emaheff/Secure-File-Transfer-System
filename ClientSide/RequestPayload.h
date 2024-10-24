#ifndef REQUEST_PAYLOAD
#define REQUEST_PAYLOAD

#include <cstdint>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <variant>
#include <stdexcept>

#include "RequestHeader.h"
#include "Constants.h"

/**
 * @class RequestPayload
 * @brief Represents the payload portion of a request sent to the server.
 *
 * The RequestPayload class encapsulates the data (payload) sent as part of a client request.
 * It provides methods to convert the payload to bytes, access fields, and set values for the various fields.
 */
class RequestPayload
{
public:
	/**
	 * @brief Constructs an empty RequestPayload.
	 */
	RequestPayload();

	/**
	 * @brief Converts the payload into a byte vector for transmission.
	 *
	 * This method serializes the payload data into a byte array based on the type of request specified by the code.
	 * @param code The operation code for determining the type of payload.
	 * @return A vector of chars representing the byte stream of the payload.
	 */
	std::vector<char> toBytes(int code);

	/**
	 * @brief Overloads the << operator to print the payload's contents.
	 *
	 * Prints all the fields stored in the payload to the output stream.
	 * @param os The output stream.
	 * @param payload The RequestPayload object to be printed.
	 * @return The output stream after printing the payload.
	 */
	friend std::ostream& operator<<(std::ostream& os, const RequestPayload& payload);

	/**
	 * @brief Calculates the total size of the payload.
	 *
	 * This method sums up the size of each field in the payload and returns the total size in bytes.
	 * @return The total size of the payload in bytes.
	 */
	int size();

	/**
	 * @brief Retrieves the value of a specific field in the payload by name.
	 *
	 * This method returns the value of the requested field if it exists in the payload.
	 * @param fieldName The name of the field to retrieve.
	 * @return A std::variant containing either int, unsigned long, or std::string depending on the field.
	 */
	std::variant<int, unsigned long, std::string> getField(const std::string& fieldName) const;

	// Setters for various fields in the payload
	void setContentSize(int size);
	void setOrigFileSize(int size);
	void setPacketNumber(int number);
	void setTotalPackets(int number);
	void setFileName(const std::string& fileName);
	void setContent(const std::vector<char>& content);
	void setUserName(const std::string& userName);
	void setPublicKey(const std::string& publicKey);



private:
	/**
	 * @brief Internal storage of the payload fields as a vector of name-value pairs.
	 * Each field is represented by a pair where the first element is the field name and the second is its value.
	 */
	std::vector<std::pair<std::string, std::variant<int, unsigned long, std::string>>> payload;

	/**
	 * @brief Converts an integer into a vector of bytes (little-endian).
	 *
	 * This method converts an integer into a fixed number of bytes (numOfBytes) using little-endian format.
	 * @param number The integer to convert.
	 * @param numOfBytes The number of bytes to represent the integer.
	 * @return A vector of chars representing the integer as bytes.
	 */
	std::vector<char> intToBytes(int number, size_t numOfBytes);

	/**
	 * @brief Converts a string into a fixed-size vector of chars.
	 *
	 * The string is copied into a vector of chars, and the remaining space is filled with null terminators.
	 * @param str The string to convert.
	 * @param n The size of the resulting vector.
	 * @return A vector of chars with the string and padding.
	 */
	std::vector<char> stringToFixedSizeVector(const std::string& str, size_t n);

};
#endif // !REQUESTPAYLOAD

#include "ResponsePayload.h"


/**
 * @brief Constructs a ResponsePayload object by parsing the provided header and payload data.
 *
 * This constructor processes the response payload according to the operation code from the header.
 * It extracts fields such as client ID, file name, and content size depending on the code.
 *
 * @param code The operation code associated with this payload.
 * @param payloadData The raw byte data of the payload.
 */
ResponsePayload::ResponsePayload(int code, const std::vector<char>& payloadData) {
    size_t offset = 0; // Current reading position in payloadData

    try {
        if (code == ResponseHeader::Code::RegistrationSuccess ||
            code == ResponseHeader::Code::MessageReceived ||
            code == ResponseHeader::Code::ReconnectionFailure) {
            // Only field is client ID (16 bytes)
            std::vector<char> clientIdVec(payloadData.begin() + offset, payloadData.begin() + offset + Constants::CLIENT_ID_SIZE);
            std::string clientId = hexify(clientIdVec);
            attributes.push_back({ "client_id", clientId });
        }
        else if (code == ResponseHeader::Code::RegistrationFailure || code == ResponseHeader::Code::GeneralError) {
            // No payload
        }
        else if (code == ResponseHeader::Code::PublicKeyReceived || code == ResponseHeader::Code::ReconnectionSuccess) {
            // Client ID (16 bytes)
            std::vector<char> clientIdVec(payloadData.begin() + offset, payloadData.begin() + offset + Constants::CLIENT_ID_SIZE);
            std::string clientId = hexify(clientIdVec);
            attributes.push_back({ "client_id", clientId });
            offset += Constants::CLIENT_ID_SIZE;

            // AES Symmetric Key (remaining bytes)
            size_t keySize = payloadData.size() - offset;
            std::string aesKey = readString(payloadData, offset, keySize);
            attributes.push_back({ "aes_key", aesKey });
        }
        else if (code == ResponseHeader::Code::FileReceived) {
            // Client ID (16 bytes)
            std::vector<char> clientIdVec(payloadData.begin() + offset, payloadData.begin() + offset + Constants::CLIENT_ID_SIZE);
            std::string clientId = hexify(clientIdVec);
            attributes.push_back({ "client_id", clientId });
            offset += Constants::CLIENT_ID_SIZE;

            // Content Size (4 bytes)
            int contentSize = readNumber(payloadData, offset, Constants::CONTENT_SIZE_SIZE);
            attributes.push_back({ "content_size", contentSize });
            offset += Constants::CONTENT_SIZE_SIZE;

            // File Name (255 bytes)
            std::string fileName = readString(payloadData, offset, Constants::FILE_NAME_SIZE);
            attributes.push_back({ "file_name", fileName });
            offset += Constants::FILE_NAME_SIZE;

            // Checksum (4 bytes)
            unsigned long cksum = readNumber(payloadData, offset, Constants::CKSUM_SIZE);
            attributes.push_back({ "cksum", cksum });
            offset += Constants::CKSUM_SIZE;
        }
        else {
            // Handle unknown codes if necessary
            throw std::invalid_argument("Unknown response code");
        }
    }
    catch (const std::out_of_range& e) {
        // Handle errors if payloadData is not sufficient
        throw std::runtime_error("Failed to parse ResponsePayload: " + std::string(e.what()));
    }
}

/**
 * @brief Overloads the << operator to print the contents of the payload.
 *
 * This method prints all the attributes stored in the payload, including fields like client ID, file name, etc.
 * @param os The output stream to print to.
 * @param payload The ResponsePayload object to print.
 * @return The output stream after printing the payload.
 */
std::ostream& operator<<(std::ostream& os, const ResponsePayload& payload) {
    os << "Response Payload:\n";
    for (const auto& attr : payload.attributes) {
        os << attr.first << ": ";
        if (std::holds_alternative<int>(attr.second)) {
            os << std::get<int>(attr.second);
        }
        else if (std::holds_alternative<unsigned long>(attr.second)) {
            os << std::get<unsigned long>(attr.second);
        }
        else if (std::holds_alternative<std::string>(attr.second)) {
            os << std::get<std::string>(attr.second);
        }
        os << "\n";
    }
    return os;
}

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
std::variant<int, unsigned long, std::string> ResponsePayload::getField(const std::string& fieldName) const {
    // Iterate through attributes to find the field with the specified name
    for (const auto& attr : attributes) {
        if (attr.first == fieldName) {
            return attr.second;
        }
    }
    // If the field is not found, throw an exception
    throw std::invalid_argument("Field not found: " + fieldName);
}

/**
 * @brief Converts a vector of bytes to a hexadecimal string.
 *
 * This method converts each byte in the buffer to its corresponding hexadecimal value, resulting in a string.
 * @param buffer The vector of bytes to convert.
 * @return The hexadecimal string representation of the byte vector.
 */
std::string ResponsePayload::hexify(const std::vector<char>& buffer) {
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < buffer.size(); ++i) {
        ss << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);
    }
    return ss.str();
}

/**
 * @brief Reads an integer from the provided data at the specified offset.
 *
 * This method reads a specified number of bytes from the data vector starting at the given offset, and interprets it
 * as an integer in little-endian format.
 *
 * @param data The data vector to read from.
 * @param offset The starting position in the data vector.
 * @param byteCount The number of bytes to read.
 * @return The integer value read from the data.
 * @throws std::out_of_range if there are not enough bytes to read.
 */
int ResponsePayload::readNumber(const std::vector<char>& data, size_t offset, size_t byteCount) const {
    if (offset + byteCount > data.size()) {
        throw std::out_of_range("Not enough data to read the number of bytes");
    }

    int value = 0;
    for (size_t i = 0; i < byteCount; ++i) {
        value |= (static_cast<unsigned char>(data[offset + i]) << (i * 8)); // Shift by i * 8 to reflect little-endian
    }

    return value;
}

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
std::string ResponsePayload::readString(const std::vector<char>& data, size_t offset, size_t length) const {
    if (offset + length > data.size()) {
        throw std::out_of_range("Not enough data to read a string");
    }
    return std::string(data.begin() + offset, data.begin() + offset + length);
}

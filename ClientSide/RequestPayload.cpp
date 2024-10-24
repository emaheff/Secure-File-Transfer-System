#include "RequestPayload.h"

/**
 * @brief Default constructor for the RequestPayload class.
 *
 * Initializes the payload as an empty vector.
 */
RequestPayload::RequestPayload() : payload() { }

// Setters for various fields in the payload
void RequestPayload::setOrigFileSize(int size) {
    payload.push_back({ "orig file size", size });
}

void RequestPayload::setPacketNumber(int number) {
    payload.push_back({ "packet number", number });
}

void RequestPayload::setTotalPackets(int number) {
    payload.push_back({ "total packets", number });
}

void RequestPayload::setFileName(const std::string& fileName) {
    payload.push_back({ "file name", fileName });
}

void RequestPayload::setContentSize(int size) {
	payload.push_back({ "content size", size });
}

void RequestPayload::setContent(const std::vector<char>& content) {
    std::string contentStr(content.begin(), content.end());
    payload.push_back({ "content", contentStr });
}

void RequestPayload::setUserName(const std::string& userName) {
	payload.push_back({ "user name", userName });
}

void RequestPayload::setPublicKey(const std::string& publicKey) {
	payload.push_back({ "public key", publicKey });
}

/**
 * @brief Overloads the << operator to print the contents of the payload.
 *
 * This method iterates through all fields stored in the payload and prints their names and values.
 * It handles fields of different types (int, unsigned long, and string) by checking their types using `std::holds_alternative`
 * and then prints the appropriate value.
 *
 * @param os The output stream where the payload will be printed.
 * @param payload The RequestPayload object whose fields will be printed.
 * @return The output stream after printing the payload's fields.
 */
std::ostream& operator<<(std::ostream& os, const RequestPayload& payload) {
    for (const auto& field : payload.payload) {
        os << field.first << ": ";
        if (std::holds_alternative<int>(field.second)) {
            os << std::get<int>(field.second);
        }
        else if (std::holds_alternative<unsigned long>(field.second)) {
            os << std::get<unsigned long>(field.second);
        }
        else if (std::holds_alternative<std::string>(field.second)) {
            os << std::get<std::string>(field.second);
        }
        os << "\n";
    }
    return os;
}

/**
 * @brief Retrieves the value of a specific field in the payload by its name.
 *
 * This method searches through the payload's fields for a field with the specified name.
 * If the field is found, it returns its value as a `std::variant<int, unsigned long, std::string>`.
 * If the field is not found, it returns an empty variant.
 *
 * @param fieldName The name of the field to retrieve.
 * @return A std::variant containing either an int, unsigned long, or std::string representing the field's value.
 */
std::variant<int, unsigned long, std::string> RequestPayload::getField(const std::string& fieldName) const {
	// Iterate through the payload to find the field with the specified name
	for (const auto& field : payload) {
		if (field.first == fieldName) {
			return field.second;
		}
	}

	// Return an empty variant if the field is not found
	return std::variant<int, unsigned long, std::string>();
}

/**
 * @brief Converts the payload into a byte vector for transmission.
 *
 * This method serializes the payload fields into a byte array,
 * with different handling based on the request code.
 * @param code The operation code for determining the type of payload.
 * @return A vector of chars representing the byte stream of the payload.
 */
std::vector<char> RequestPayload::toBytes(int code) {
    std::vector<char> bytes;

    // Convert the payload based on the code
    switch (code) {
    case RequestHeader::Code::RegistrationCode:
    case RequestHeader::Code::ReconnectingCode:
    {
        std::string userName = std::get<std::string>(RequestPayload::getField("user name"));
        std::vector<char> userNameVec = stringToFixedSizeVector(userName, Constants::USERNAME_SIZE);
        bytes.insert(bytes.end(), userNameVec.begin(), userNameVec.end());
    }
    break;

    case RequestHeader::Code::PublicKeyCode:
    {
        std::string userName = std::get<std::string>(RequestPayload::getField("user name"));
        std::vector<char> userNameVec = stringToFixedSizeVector(userName, Constants::USERNAME_SIZE);
        bytes.insert(bytes.end(), userNameVec.begin(), userNameVec.end());

        // Convert PublicKey to bytes (160 bytes, little-endian)
        std::string publicKey = std::get<std::string>(RequestPayload::getField("public key"));
		std::vector<char> publicKeyVec(publicKey.begin(), publicKey.end());
        bytes.insert(bytes.end(), publicKeyVec.begin(), publicKeyVec.end());
    }
    break;

    case RequestHeader::Code::SendFileCode:
    {
        // Convert content size (4 bytes, little-endian)
        int contentSize = std::get<int>(RequestPayload::getField("content size"));
        std::vector<char> contentSizeVec = intToBytes(contentSize, Constants::CONTENT_SIZE_SIZE);
        bytes.insert(bytes.end(), contentSizeVec.begin(), contentSizeVec.end());

        // Convert orig file size (4 bytes, little-endian)
        int origFileSize = std::get<int>(RequestPayload::getField("orig file size"));
        std::vector<char> origFileSizeVec = intToBytes(origFileSize, Constants::ORIG_FILE_SIZE_SIZE);
        bytes.insert(bytes.end(), origFileSizeVec.begin(), origFileSizeVec.end());

        // Convert packet number (4 bytes, little-endian)
        int packetNumber = std::get<int>(RequestPayload::getField("packet number"));
        std::vector<char> packetNumberVec = intToBytes(packetNumber, Constants::PACKET_NUMBER_SIZE);
        bytes.insert(bytes.end(), packetNumberVec.begin(), packetNumberVec.end());

        // Convert total packets (4 bytes, little-endian)
        int totalPackets = std::get<int>(RequestPayload::getField("total packets"));
        std::vector<char> totalPacketsVec = intToBytes(totalPackets, Constants::TOTAL_PACKET_SIZE);
        bytes.insert(bytes.end(), totalPacketsVec.begin(), totalPacketsVec.end());

        // Convert file name (255 bytes)
        std::string fileName = std::get<std::string>(RequestPayload::getField("file name"));
        std::vector<char> fileNameVec = stringToFixedSizeVector(fileName, Constants::FILE_NAME_SIZE);
        bytes.insert(bytes.end(), fileNameVec.begin(), fileNameVec.end());

        // Convert content (variable size)
        std::string content = std::get<std::string>(RequestPayload::getField("content"));
		std::vector<char> contentVec(content.begin(), content.end());
        bytes.insert(bytes.end(), contentVec.begin(), contentVec.end());
    }
    break;

    case RequestHeader::Code::ValidCRC:
    case RequestHeader::Code::NotValidCRC:
    case RequestHeader::Code::NotValidCRC4th:
    {
        // Convert the file name to bytes (255 bytes)
        std::string fileName = std::get<std::string>(RequestPayload::getField("file name"));
        std::vector<char> fileNameVec = stringToFixedSizeVector(fileName, Constants::FILE_NAME_SIZE);
        bytes.insert(bytes.end(), fileNameVec.begin(), fileNameVec.end());
    }
    break;
    }

    return bytes;
}

/**
 * @brief Calculates the total size of the payload.
 *
 * This method sums up the size of each field in the payload and returns the total size in bytes.
 * @return The total size of the payload in bytes.
 */
int RequestPayload::size() {
    int totalSize = 0;

    for (const auto& field : payload) {
        if (field.first == "user name") {
            totalSize += Constants::USERNAME_SIZE;
        }
        else if (field.first == "file name") {
            totalSize += Constants::FILE_NAME_SIZE;
        }
        else if (field.first == "public key") {
            totalSize += Constants::PUBLIC_KEY_SIZE;
        }
        else if (field.first == "packet number") {
            totalSize += Constants::PACKET_NUMBER_SIZE;
        }
        else if (field.first == "total packets") {
            totalSize += Constants::TOTAL_PACKET_SIZE;
        }
        else if (field.first == "content size") {
            totalSize += Constants::CONTENT_SIZE_SIZE;
        }
        else if (field.first == "orig file size") {
            totalSize += Constants::ORIG_FILE_SIZE_SIZE;
        }
        else if (field.first == "content") {
            // Variable size content (size is the length of the string)
            totalSize += std::get<std::string>(field.second).size();
        }
    }

    return totalSize;
}

/**
 * @brief Converts an integer into a vector of bytes (little-endian).
 *
 * This method converts an integer into a fixed number of bytes (numOfBytes) using little-endian format.
 * @param number The integer to convert.
 * @param numOfBytes The number of bytes to represent the integer.
 * @return A vector of chars representing the integer as bytes.
 */
std::vector<char> RequestPayload::intToBytes(int number, size_t numOfBytes) {
    // Check if the requested number of bytes is valid (e.g., between 1 and sizeof(int))
    if (numOfBytes > sizeof(int)) {
        throw std::invalid_argument("Requested byte size exceeds the size of int.");
    }

    std::vector<char> bytes(numOfBytes);

    // Extract each byte and store it in the vector (little-endian order)
    for (size_t i = 0; i < numOfBytes; ++i) {
        bytes[i] = static_cast<char>((number >> (8 * i)) & 0xFF);
    }

    return bytes;
}


/**
 * @brief Converts a string into a fixed-size vector of chars.
 *
 * The string is copied into a vector of chars, and the remaining space is filled with null terminators.
 * @param str The string to convert.
 * @param n The size of the resulting vector.
 * @return A vector of chars with the string and padding.
 */
std::vector<char> RequestPayload::stringToFixedSizeVector(const std::string& str, size_t n) {
    if (n == 0) {
        throw std::invalid_argument("Size n must be greater than 0.");
    }

    std::vector<char> charVector(n, '\0');  // Create a vector of size n, filled with null terminators

    // Copy the string into the vector, ensuring it does not exceed size n - 1
    size_t copyLength = (str.size() < n - 1) ? str.size() : n - 1;
    std::copy(str.begin(), str.begin() + copyLength, charVector.begin());

    // The null terminator is automatically in place because the vector was initialized with '\0'

    return charVector;
}






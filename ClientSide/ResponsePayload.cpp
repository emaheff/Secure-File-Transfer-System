#include "ResponsePayload.h"
#include "ResponseHeader.h" // Include the ResponseHeader definition

// Helper function to convert a vector of bytes to a hex string
std::string ResponsePayload::hexify(const std::vector<char>& buffer) {
    std::stringstream ss;
    ss << std::hex;
    for (size_t i = 0; i < buffer.size(); ++i) {
        ss << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]);
    }
    return ss.str();
}

// Helper function to read an integer from a vector of chars
unsigned long ResponsePayload::readInt(const std::vector<char>& data, size_t offset) const {
    if (offset + 4 > data.size()) {
        throw std::out_of_range("Not enough data to read an int");
    }
    uint32_t value = (static_cast<uint8_t>(data[offset]) << 24) |
        (static_cast<uint8_t>(data[offset + 1]) << 16) |
        (static_cast<uint8_t>(data[offset + 2]) << 8) |
        (static_cast<uint8_t>(data[offset + 3]));
    return static_cast<unsigned long>(value);
}

// Helper function to read a string from a vector of chars
std::string ResponsePayload::readString(const std::vector<char>& data, size_t offset, size_t length) const {
    if (offset + length > data.size()) {
        throw std::out_of_range("Not enough data to read a string");
    }
    return std::string(data.begin() + offset, data.begin() + offset + length);
}

// Constructor for the ResponsePayload class
// Constructor for the ResponsePayload class
ResponsePayload::ResponsePayload(const ResponseHeader& header, const std::vector<char>& payloadData) {
    int code = header.getCode();
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
            int contentSize = readInt(payloadData, offset);
            attributes.push_back({ "content_size", contentSize });
            offset += Constants::CONTENT_SIZE_SIZE;

            // File Name (255 bytes)
            std::string fileName = readString(payloadData, offset, Constants::FILE_NAME_SIZE);
            attributes.push_back({ "file_name", fileName });
            offset += Constants::FILE_NAME_SIZE;

            // Checksum (4 bytes)
            unsigned long cksum = readInt(payloadData, offset);
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


// Method to convert the payload data into a human-readable string
std::string ResponsePayload::toString() const {
    std::ostringstream oss;
	oss << "Response Payload:\n";
    for (const auto& attr : attributes) {
        oss << attr.first << ": ";
        if (std::holds_alternative<int>(attr.second)) {
            oss << std::get<int>(attr.second);
        }
        else if (std::holds_alternative<std::string>(attr.second)) {
            oss << std::get<std::string>(attr.second);
        }
        oss << "\n";
    }
    return oss.str();
}

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



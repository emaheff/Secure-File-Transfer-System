#include "RequestPayload.h"
#include <stdexcept>

RequestPayload::RequestPayload() : payload() { }

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

std::vector<char> RequestPayload::getFlattenedPayload() const {
    std::vector<char> flattenedPayload;

    // Reserve enough space to minimize reallocations (optional, but improves performance)
    size_t totalSize = 0;
    for (const auto& field : payload) {
        totalSize += field.size();
    }
    flattenedPayload.reserve(totalSize);

    // Iterate through the payload and append each inner vector
    for (const auto& field : payload) {
        flattenedPayload.insert(flattenedPayload.end(), field.begin(), field.end());
    }

    return flattenedPayload;
}

void RequestPayload::addToPayload(std::vector<char> field) {
	payload.push_back(field);
}

int RequestPayload::size() const {
    size_t totalSize = 0;

    // Sum the size of all the inner vectors
    for (const auto& field : payload) {
        totalSize += field.size();
    }

    return static_cast<int>(totalSize);
}

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



#ifndef RESPONSEPAYLOAD_H
#define RESPONSEPAYLOAD_H

#include <string>
#include <vector>
#include <variant>
#include <sstream>
#include <stdexcept>
#include "Constants.h"
#include "RSAWrapper.h"
#include "Base64Wrapper.h"
#include "AESWrapper.h"
#include <iomanip>

// Forward declaration of ResponseHeader class (assumed to be defined elsewhere)
class ResponseHeader;

// The ResponsePayload class definition
class ResponsePayload {
public:
    // Constructor
    ResponsePayload(const ResponseHeader& header, const std::vector<char>& payloadData);

    // Method to return string representation of the payload
    std::string toString() const;

    // Method to get a field from the payload
    std::variant<int, unsigned long, std::string> getField(const std::string& fieldName) const;



private:
    // Attributes: vector of pairs where the first is field name and second is value (int or string)
    std::vector<std::pair<std::string, std::variant<int, unsigned long, std::string>>> attributes;

    // Helper functions
    unsigned long readInt(const std::vector<char>& data, size_t offset) const;
    std::string readString(const std::vector<char>& data, size_t offset, size_t length) const;

    std::string hexify(const std::vector<char>& buffer);
};
#endif // RESPONSEPAYLOAD_H

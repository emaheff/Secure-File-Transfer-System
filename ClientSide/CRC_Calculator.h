#ifndef CRC_CALCULATOR_H
#define CRC_CALCULATOR_H

#include <vector>
#include <cstdint>
#include <string>

class CRC_Calculator {
public:
    // Add the new method for reading the file and calculating the CRC
    static unsigned long readFile(const std::string& filePath);

    // Existing method to calculate CRC32 of the given data
    static unsigned long memcrc(char* b, size_t n);

private:
    // Precomputed CRC table
    static const uint32_t crctab[8][256];
};

#endif // CRC_CALCULATOR_H

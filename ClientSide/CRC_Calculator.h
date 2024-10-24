#ifndef CRC_CALCULATOR_H
#define CRC_CALCULATOR_H

#include <vector>
#include <cstdint>
#include <string>

/**
 * @class CRC_Calculator
 * @brief This class provides methods for calculating CRC32 checksums.
 */
class CRC_Calculator {
public:
    /**
     * @brief Reads the content of a file and calculates the CRC32 checksum.
     * @param filePath The path to the file whose CRC is to be calculated.
     * @return The calculated CRC32 checksum.
     */
    static unsigned long readFile(const std::string& filePath);


private:
    /**
     * @brief Precomputed CRC32 table for optimized calculations.
     */
    static const uint32_t crctab[8][256];

    /**
     * @brief Calculates the CRC32 checksum of a memory buffer.
     * @param b Pointer to the buffer.
     * @param n The number of bytes in the buffer.
     * @return The calculated CRC32 checksum.
     */
    static unsigned long memcrc(char* b, size_t n);
};

#endif // CRC_CALCULATOR_H

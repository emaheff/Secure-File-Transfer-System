#ifndef CRC32CALCULATOR_H
#define CRC32CALCULATOR_H

#include <vector>
#include <cstdint>
#include <string>

class CRC32Calculator {
public:
    // Method to calculate CRC32 of the given data
    static unsigned long calculate(const std::vector<char>& data);

private:
    // Precomputed CRC table
    static const uint32_t crctab[8][256];
};

#endif // CRC32CALCULATOR_H

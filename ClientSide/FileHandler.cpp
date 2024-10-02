#include "FileHandler.h"
#include <fstream>
#include <stdexcept>



bool FileHandler::isFileExist(const std::string& fileName)
{
	std::ifstream file(fileName);
	return file.good();
}

std::string FileHandler::getSpecificLine(const std::string& filePath, size_t lineNumber) {
    std::ifstream file(filePath);

    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + filePath);
    }

    std::string line;
    size_t currentLine = 1; // Line numbers usually start from 1

    while (std::getline(file, line)) {
        if (currentLine == lineNumber) {
            return line;
        }
        currentLine++;
    }

    // If the line number was out of range, throw an error or return an empty string
    throw std::out_of_range("Line number " + std::to_string(lineNumber) + " out of range in file: " + filePath);
}


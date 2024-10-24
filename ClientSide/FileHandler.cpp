#include "FileHandler.h"
#include <fstream>
#include <stdexcept>


/**
 * @brief Checks if the specified file exists.
 * @param fileName The name of the file to check.
 * @return true if the file exists, false otherwise.
 */
bool FileHandler::isFileExist(const std::string& fileName)
{
	std::ifstream file(fileName);
	return file.good();
}

/**
 * @brief Retrieves a specific line from a file.
 * @param filePath The path to the file.
 * @param lineNumber The line number to retrieve (starting from 1).
 * @return The content of the specified line.
 * @throws std::runtime_error if the file could not be opened.
 * @throws std::out_of_range if the specified line number exceeds the number of lines in the file.
 */
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


/**
 * @brief Writes the given content to a specified file.
 * If the file already exists, its content will be overwritten.
 * @param fileName The name of the file to write to.
 * @param content The content to be written to the file.
 * @throws std::runtime_error if the file could not be opened for writing.
 */
void FileHandler::writeToFile(const std::string& fileName, const std::string& content) {
	std::ofstream file(fileName);

	if (!file.is_open()) {
		throw std::runtime_error("Could not open file: " + fileName);
	}

	file << content;
	file.close();
}

/**
 * @brief Appends the given content to the end of a specified file.
 * If the file does not exist, it will be created.
 * @param fileName The name of the file to write to.
 * @param content The content to append to the file.
 * @throws std::runtime_error if the file could not be opened for writing.
 */
void FileHandler::appendToFile(const std::string& fileName, const std::string& content) {
    std::ofstream file(fileName, std::ios::out | std::ios::app); // Open file in append mode

    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + fileName);
    }

    file << content; // Append the content at the end of the file
    file.close();
}

/**
 * @brief Returns the size of the specified file in bytes.
 * @param filePath The path to the file.
 * @return The size of the file in bytes.
 * @throws std::runtime_error if the file could not be opened.
 */
int FileHandler::getFileSize(const std::string& filePath) {
	std::ifstream file(filePath, std::ios::binary | std::ios::ate);
	return file.tellg();
}

/**
 * @brief Writes binary content to a specified file.
 * @param fileName The name of the file to write to.
 * @param content The binary content to write.
 * @throws std::runtime_error if the file could not be opened for writing.
 */
void FileHandler::writeToBinaryFile(const std::string& fileName, const std::string& content) {
    std::ofstream file(fileName, std::ios::out | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + fileName);
    }
    file.write(content.c_str(), content.size());
    file.close();
}

/**
 * @brief Reads binary content from a specified file.
 * @param fileName The name of the file to read from.
 * @return A string containing the binary data read from the file.
 * @throws std::runtime_error if the file could not be opened for reading.
 */std::string FileHandler::readFromBinaryFile(const std::string& fileName) {
    std::ifstream file(fileName, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open file: " + fileName);
    }
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    return content;
}

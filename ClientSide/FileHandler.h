#ifndef FILE_HANDLER
#define FILE_HANDLER

#include <string>

/**
 * @class FileHandler
 * @brief A utility class for handling file-related operations such as reading, writing, and checking file existence.
 *
 * The FileHandler class provides static methods for performing common file operations, such as checking if a file exists,
 * reading a specific line from a file, getting the file size, and handling binary file read/write operations.
 */
class FileHandler
{
public:

	/**
	 * @brief Writes the given content to a specified file.
	 * If the file already exists, its content will be overwritten.
	 * @param fileName The name of the file to write to.
	 * @param content The content to be written to the file.
	 * @throws std::runtime_error if the file could not be opened for writing.
	 */
	static void writeToFile(const std::string& fileName, const std::string& content);

	/**
	 * @brief Checks if the specified file exists.
	 * @param fileName The name of the file to check.
	 * @return true if the file exists, false otherwise.
	 */
	static bool isFileExist(const std::string& fileName);

	/**
	 * @brief Retrieves a specific line from a file.
	 * @param filePath The path to the file.
	 * @param lineNumber The line number to retrieve (starting from 1).
	 * @return The content of the specified line.
	 * @throws std::runtime_error if the file could not be opened.
	 * @throws std::out_of_range if the specified line number exceeds the number of lines in the file.
	 */
	static std::string getSpecificLine(const std::string& filePath, size_t lineNumber);

	/**
	 * @brief Returns the size of the specified file in bytes.
	 * @param filePath The path to the file.
	 * @return The size of the file in bytes.
	 * @throws std::runtime_error if the file could not be opened.
	 */
	static int getFileSize(const std::string& filePath);

	/**
	 * @brief Writes binary content to a specified file.
	 * @param fileName The name of the file to write to.
	 * @param content The binary content to write.
	 * @throws std::runtime_error if the file could not be opened for writing.
	 */
	static void writeToBinaryFile(const std::string& fileName, const std::string& content);

	/**
	 * @brief Reads binary content from a specified file.
	 * @param fileName The name of the file to read from.
	 * @return A string containing the binary data read from the file.
	 * @throws std::runtime_error if the file could not be opened for reading.
	 */
	static std::string readFromBinaryFile(const std::string& fileName);

	/**
	 * @brief Appends the given content to the end of a specified file.
	 * If the file does not exist, it will be created.
	 * @param fileName The name of the file to write to.
	 * @param content The content to append to the file.
	 * @throws std::runtime_error if the file could not be opened for writing.
	 */
	static void appendToFile(const std::string& fileName, const std::string& content);
};

#endif // !FILE_HANDLER

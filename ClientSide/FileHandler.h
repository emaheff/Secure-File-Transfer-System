#ifndef FILE_HANDLER
#define FILE_HANDLER

#include <string>

class FileHandler
{
public:
	
	static void writeToFile(const std::string& fileName, const std::string& content);
	static bool isFileExist(const std::string& fileName);
	static std::string getSpecificLine(const std::string& filePath, size_t lineNumber);
	static int getFileSize(const std::string& filePath);

};

#endif // !FILE_HANDLER

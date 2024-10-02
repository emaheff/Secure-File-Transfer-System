#ifndef FILE_HANDLER
#define FILE_HANDLER

#include <string>

class FileHandler
{
public:
	

	static bool isFileExist(const std::string& fileName);
	static std::string getSpecificLine(const std::string& filePath, size_t lineNumber);

};

#endif // !FILE_HANDLER

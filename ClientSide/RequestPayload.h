#ifndef REQUEST_PAYLOAD
#define REQUEST_PAYLOAD

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
class RequestPayload
{
public:
	RequestPayload();
	
	std::vector<char> intToBytes(int number, size_t numOfBytes);
	void addToPayload(std::vector<char> field);
	std::vector<char> getFlattenedPayload() const;
	std::vector<char> stringToFixedSizeVector(const std::string& str, size_t n);
	int size() const;
	std::string toString() const;

	void setContentSize(int size);
	void setOrigFileSize(int size);
	void setPacketNumber(int number);
	void setTotalPackets(int number);
	void setFileName(const std::string& fileName);
	void setContent(const std::vector<char>& content);



private:
	std::vector<std::vector<char>> payload;
	


};
#endif // !REQUESTPAYLOAD

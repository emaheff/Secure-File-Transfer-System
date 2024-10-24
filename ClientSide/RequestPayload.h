#ifndef REQUEST_PAYLOAD
#define REQUEST_PAYLOAD

#include <cstdint>
#include <vector>
#include <array>
#include <string>
#include <sstream>
#include <iomanip>
#include <variant>
#include "RequestHeader.h"
#include "Constants.h"
class RequestPayload
{
public:
	RequestPayload();
	
	std::vector<char> intToBytes(int number, size_t numOfBytes);
	std::vector<char> toBytes(int code);
	std::vector<char> stringToFixedSizeVector(const std::string& str, size_t n);
	std::string toString() const;

	int size();

	std::variant<int, unsigned long, std::string> getField(const std::string& fieldName) const;

	void setContentSize(int size);
	void setOrigFileSize(int size);
	void setPacketNumber(int number);
	void setTotalPackets(int number);
	void setFileName(const std::string& fileName);
	void setContent(const std::vector<char>& content);
	void setUserName(const std::string& userName);
	void setPublicKey(const std::string& publicKey);



private:
	std::vector<std::pair<std::string, std::variant<int, unsigned long, std::string>>> payload;

};
#endif // !REQUESTPAYLOAD

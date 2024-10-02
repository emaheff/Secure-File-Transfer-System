#ifndef REQUEST_PAYLOAD
#define REQUEST_PAYLOAD

#include <cstdint>
#include <vector>
#include <array>
#include <string>

class RequestPayload
{
public:
	RequestPayload();
	
	std::vector<char> intToBytes(int number, size_t numOfBytes);
	void addToPayload(std::vector<char> field);
	std::vector<char> getFlattenedPayload() const;
	std::vector<char> stringToFixedSizeVector(const std::string& str, size_t n);
	int size() const;



private:
	std::vector<std::vector<char>> payload;
	


};
#endif // !REQUESTPAYLOAD

#ifndef REQUEST
#define REQUEST

#include "RequestHeader.h"
#include "RequestPayload.h"

class Request {
public:
	Request(RequestHeader header, RequestPayload payload);
	
	std::vector<char> toBytes();
	int size();
	std::string toString() const;

private:
	RequestHeader header;
	RequestPayload payload;
};

#endif // !REQUEST

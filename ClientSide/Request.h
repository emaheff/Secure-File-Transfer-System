#ifndef REQUEST
#define REQUEST

#include "RequestHeader.h"
#include "RequestPayload.h"

class Request {
public:
	Request(RequestHeader header, RequestPayload payload);
	
	std::vector<char> toBytes() const;
	int size() const;

private:
	RequestHeader header;
	RequestPayload payload;
};

#endif // !REQUEST

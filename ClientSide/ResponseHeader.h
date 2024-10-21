#ifndef RESPONSE_HEADER
#define RESPONSE_HEADER

#include <vector>
#include "ResponsePayload.h"

class ResponseHeader
{
public:
	ResponseHeader(std::vector<char> rawData);
	int getCode() const;
	int getPayloadSize() const;
    std::string toString() const;

    enum Code {
        RegistrationSuccess = 1600,
        RegistrationFailure = 1601,
        PublicKeyReceived = 1602,
        FileReceived = 1603,
        MessageReceived = 1604,
        ReconnectionSuccess = 1605,
        ReconnectionFailure = 1606,
        GeneralError = 1607
    };

private:
	int version;
	int code;
	int payloadSize;
};
#endif // !RESPONSE_HEADER

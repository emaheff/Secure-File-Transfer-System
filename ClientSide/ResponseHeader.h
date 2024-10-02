#ifndef RESPONSE_HEADER
#define RESPONSE_HEADER

#include <vector>

class ResponseHeader
{
public:
	ResponseHeader(std::vector<char> rawData);
	int getCode() const;
	int getPayloadSize() const;

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

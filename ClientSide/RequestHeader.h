#ifndef REQUEST_HEADER
#define REQUEST_HEADER

#include <cstdint>
#include <array>
#include <string>
#include <vector>

class RequestHeader
{
public:
	RequestHeader(std::string clientID, int version, int code, int payloadSize);

	std::vector<char> toBytes() const;
	int size() const;
    std::string toString() const;

    static const int VERSION;

    // Define enums for the codes
    enum Code {
        RegistrationCode = 825,
        PublicKeyCode = 826,
        ReconnectingCode = 827,
        SendFileCode = 828,
        ValidCRC = 900,
        NotValidCRC = 901,
        NotValidCRC4th = 902
    };

private:
	std::string clientID;
	int version;
    int code;
    int payloadSize;
};
#endif // !REQUESTHEADER

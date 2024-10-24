#ifndef CLIENTSESSION_H
#define CLIENTSESSION_H

#include <boost/asio.hpp>
#include <string>
#include <vector>
#include "Request.h"
#include "RequestHeader.h"
#include "RequestPayload.h"
#include "ResponseHeader.h"
#include "FileHandler.h"
#include "Constants.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "CRC_Calculator.h"
#include <rsa.h>
#include <osrng.h>
#include <files.h>
#include <base64.h>


std::string hexify(const std::vector<char>& buffer);

class ClientSession {
public:
    // Constructor - establishes a connection to the server
    ClientSession(const std::string& address, const std::string& port);

    // Attempt to reconnect to the server using stored credentials
    ResponseHeader reconnect();

    // Register the user with the server if reconnection fails
    ResponseHeader registerUser(std::string& userName);

	unsigned long getMyCRC(std::string& filePath);

	unsigned long getServerCRC(std::string& filePath, std::vector<char> encryptedAesKey);

    // Receive and process the server's response
    ResponseHeader receiveResponseHeader();

	ResponsePayload receiveResponsePayload(ResponseHeader responseHeader);

    ResponseHeader processClientIDAndSendPublicKey(ResponsePayload responsePayload, std::string& userName);



private:
    // Boost ASIO context and socket for network operations
    boost::asio::io_context io_context;
    boost::asio::ip::tcp::socket socket;
    boost::asio::ip::tcp::resolver resolver;

    // Connect to the server with given address and port
    void connectToServer(const std::string& address, const std::string& port);

    // Prepare the reconnection request to be sent to the server
    Request prepareReconnectionRequest(const std::string& userName, const std::string& clientID);

    // Prepare the registration request to be sent to the server
    Request prepareRegistrationRequest(const std::string& userName);

    // Send a request to the server
    void sendRequest(Request& request);

    

    // Generate RSA keys and save the private key
    std::string generateAndSaveRSAKeys();

	// Prepare the public key submission request to be sent to the server
	Request preparePublicKeySubmissionRequest(const std::string& clientId, const std::string& userName, const std::string& publicKey);

    std::string decryptAESKey(const std::vector<char>& encryptedAESKey);

    std::vector<char> receiveEncryptedAESKey(ResponseHeader responseHeader);

    std::vector<char> encryptFileWithAES(const std::string& filePath, const std::vector<char>& encryptedAESKey);
};

#endif // CLIENTSESSION_H

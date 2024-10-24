#include "ClientSission.h"

using boost::asio::ip::tcp;
using namespace boost::asio;

ClientSession::ClientSession(const std::string& address, const std::string& port)
    : socket(io_context), resolver(io_context) {
    connectToServer(address, port);
}

// this method sending reconnect request to the server using the clientID and the username from the me.info file and return the response header
ResponseHeader ClientSession::reconnect() {
    std::string userName = FileHandler::getSpecificLine(Constants::ME_FILE, Constants::ME_USERNAME_LINE);
    if (userName.size() > Constants::MAX_USERNAME_LENGTH) {
        throw std::length_error("Username exceeds maximum length");
    }

    std::string clientID = FileHandler::getSpecificLine(Constants::ME_FILE, Constants::ME_CLIENT_ID_LINE);
    Request request = prepareReconnectionRequest(userName, clientID);

	std::cout << std::string(80, '-') << "\nSending reconnection request to the server...\n" << std::string(80, '-') << std::endl;

	std::cout << request.toString() << std::endl;
    sendRequest(request);
    return receiveResponseHeader();    
}

ResponseHeader ClientSession::registerUser(std::string& userName) {
    Request request = prepareRegistrationRequest(userName);
	std::cout << std::string(80, '-') << "\nSending registration request to the server...\n" << std::string(80, '-') << std::endl;
    std::cout << request.toString() << std::endl;
    sendRequest(request);

    ResponseHeader responseHeader = receiveResponseHeader();;

    int counter = 1;
    while (responseHeader.getCode() == ResponseHeader::Code::RegistrationFailure && counter <= 3) {
        request = prepareRegistrationRequest(userName);
        sendRequest(request);
        responseHeader = receiveResponseHeader();
        counter++;
    }
	return responseHeader;    
}

ResponseHeader ClientSession::processClientIDAndSendPublicKey(ResponsePayload responsePayload, std::string& userName) {
    try {
        std::string clientID = std::get<std::string>(responsePayload.getField("client_id"));

        // Save UUID to me.info
        FileHandler::writeToFile(Constants::ME_FILE, userName + "\n" + clientID);

        // generate public and private RSA keys. save the private in priv.key and send the public to the server
        std::string publicKey = generateAndSaveRSAKeys();

        // create new request such that the request header is clientID, version, code, payloadSize
        // and the payload is userName and public key
        Request publicKeyRequest = preparePublicKeySubmissionRequest(clientID, userName, publicKey);

		std::cout << std::string(80, '-') << "\nSending public key to the server...\n" << std::string(80, '-') << std::endl;

        std::cout << publicKeyRequest.toString() << std::endl;
        sendRequest(publicKeyRequest);

        ResponseHeader publicKeyResponseHeader = receiveResponseHeader();
        return publicKeyResponseHeader;
    }
    catch (const std::invalid_argument& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    catch (const std::bad_variant_access& e) {
        std::cerr << "Error: Unable to access the client_id as a string. " << e.what() << std::endl;
    }
}

void ClientSession::connectToServer(const std::string& address, const std::string& port) {
    boost::asio::connect(socket, resolver.resolve(address, port));
}

Request ClientSession::prepareReconnectionRequest(const std::string& userName, const std::string& clientID) {
    RequestPayload payload;
	payload.setUserName(userName);
    RequestHeader header(clientID, RequestHeader::VERSION, RequestHeader::Code::ReconnectingCode, payload.size());
    return Request(header, payload);
}

Request ClientSession::prepareRegistrationRequest(const std::string& userName) {
    std::string tempClientID = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    RequestHeader header(tempClientID, RequestHeader::VERSION, RequestHeader::Code::RegistrationCode, Constants::USERNAME_SIZE);
    RequestPayload payload;
	payload.setUserName(userName);
    return Request(header, payload);
}

void ClientSession::sendRequest(Request& request) {
    std::vector<char> requestBytes = request.toBytes();
    int size = requestBytes.size();
    boost::asio::write(socket, boost::asio::buffer(requestBytes, size));
}

ResponseHeader ClientSession::receiveResponseHeader() {
    std::vector<char> responseHeaderBytes(Constants::HEADER_RESPONSE_SIZE);
    boost::asio::read(socket, boost::asio::buffer(responseHeaderBytes, responseHeaderBytes.size()));
    return ResponseHeader(responseHeaderBytes);
}

std::string ClientSession::generateAndSaveRSAKeys() {
    // Generate RSA keys (private and public)
    RSAPrivateWrapper rsaPrivate;

    // Get the private key as a string
    std::string privateKeyStr = rsaPrivate.getPrivateKey();

    // Encode the private key using Base64
    std::string encodedPrivateKey = Base64Wrapper::encode(privateKeyStr);

    // Save the encoded private key to a file
    std::ofstream privFile(Constants::PRIV_FILE, std::ios::out | std::ios::binary);
    if (privFile.is_open()) {
        privFile << encodedPrivateKey;  // Save the Base64-encoded private key to the file
        privFile.close();
    }
    else {
        throw std::runtime_error("Failed to open" + Constants::PRIV_FILE + "for writing");
    }

    std::ofstream meInfoFile(Constants::ME_FILE, std::ios::app);  // Open in append mode
    if (meInfoFile.is_open()) {
        meInfoFile << "\n" << encodedPrivateKey;  // Append the private key after the last line
        meInfoFile.close();
    }
    else {
        throw std::runtime_error("Failed to open" + Constants::ME_FILE + "for appending private key");
    }

    // Get the public key from the private wrapper
    std::string publicKey = rsaPrivate.getPublicKey();


    // Return the public key vector
    return publicKey;
}



Request ClientSession::preparePublicKeySubmissionRequest(const std::string& clientId, const std::string& userName,  const std::string& publicKey) {
	RequestPayload payload;
	payload.setUserName(userName);
	payload.setPublicKey(publicKey);
	RequestHeader header(clientId, Constants::VERSION, RequestHeader::Code::PublicKeyCode, payload.size());
	return Request(header, payload);
}

std::vector<char> ClientSession::receiveEncryptedAESKey(ResponseHeader responseHeader) {
 

    // Ensure the payload size is large enough for clientID and AES key
    if (responseHeader.getPayloadSize() < 16 && responseHeader.getCode() != ResponseHeader::Code::GeneralError && responseHeader.getCode() != ResponseHeader::Code::RegistrationFailure) {
        throw std::runtime_error("Payload size is too small to contain client ID and AES key.");
    }

    // Receive the payload (client ID and encrypted AES key)
    std::vector<char> responsePayloadBytes(responseHeader.getPayloadSize());
    boost::asio::read(socket, boost::asio::buffer(responsePayloadBytes, responsePayloadBytes.size()));

    // Extract the client ID (first 16 bytes) - for future use if needed
    std::vector<char> clientID(responsePayloadBytes.begin(), responsePayloadBytes.begin() + Constants::CLIENT_ID_SIZE);

    // Extract the encrypted AES key (remaining bytes after client ID)
    std::vector<char> encryptedAESKey(responsePayloadBytes.begin() + Constants::CLIENT_ID_SIZE, responsePayloadBytes.end());

    // Return the encrypted AES key as a vector of chars
    return encryptedAESKey;
}

std::vector<char> ClientSession::encryptFileWithAES(const std::string& filePath, const std::vector<char>& encryptedAESKey) {
    // Decrypt the AES key 
    std::string decryptedAESKeyStr = decryptAESKey(encryptedAESKey);

    // Read the file content
    std::ifstream file(filePath, std::ios::in | std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open the file at the given path.");
    }
    std::vector<char> fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    // Encrypt the file content using AES
    AESWrapper aes(reinterpret_cast<const unsigned char*>(decryptedAESKeyStr.data()), decryptedAESKeyStr.size());
    std::string encryptedContent = aes.encrypt(fileContent.data(), fileContent.size());

    // Convert the encrypted content to a vector of chars and return it
    std::vector<char> encryptedFile(encryptedContent.begin(), encryptedContent.end());
    return encryptedFile;
}

std::string ClientSession::decryptAESKey(const std::vector<char>& encryptedAESKey) {
    // Load the Base64-encoded private RSA key from priv.key
    std::ifstream privFile(Constants::PRIV_FILE, std::ios::in | std::ios::binary);
    if (!privFile.is_open()) {
        throw std::runtime_error("Failed to open" + Constants::PRIV_FILE + "for reading.");
    }

    std::string encodedPrivateKey((std::istreambuf_iterator<char>(privFile)), std::istreambuf_iterator<char>());
    privFile.close();

    // Decode the private key from Base64
    std::string privateKeyStr = Base64Wrapper::decode(encodedPrivateKey);

    // Use RSAPrivateWrapper to decrypt the AES key
    RSAPrivateWrapper rsaPrivate(privateKeyStr);
    std::string decryptedAESKeyStr = rsaPrivate.decrypt(encryptedAESKey.data(), encryptedAESKey.size());

    return decryptedAESKeyStr;  // Return the decrypted AES key as a string
}


unsigned long ClientSession::getMyCRC(std::string& filePath) {
    return CRC_Calculator::readFile(filePath);
}

unsigned long ClientSession::getServerCRC(std::string& filePath, std::vector<char> encryptedAESKey){

    int origFileSize = FileHandler::getFileSize(filePath);
    std::vector<char> encryptedFile = encryptFileWithAES(filePath, encryptedAESKey);
    int encryptedFileSize = encryptedFile.size();
    int messageContentSize = Constants::PACKET_SIZE - Constants::REQUEST_HEADER_SIZE - Constants::CONTENT_SIZE_SIZE - Constants::ORIG_FILE_SIZE_SIZE - Constants::PACKET_NUMBER_SIZE
        - Constants::TOTAL_PACKET_SIZE - Constants::FILE_NAME_SIZE;
    // Calculate the number of packets to send ceiling value
    int numPackets = (encryptedFileSize + messageContentSize - 1) / messageContentSize;
	int packetNumber = 1;

	std::cout << std::string(80, '-') << "\nSending the file to the server in " << numPackets << " packets...\n" << std::string(80, '-') << std::endl;


	// Send the file in packets
    for (packetNumber; packetNumber <= numPackets; packetNumber++) {
        // create payload request
        RequestPayload payload;
        payload.setContentSize(encryptedFileSize);
        payload.setOrigFileSize(origFileSize);
        payload.setPacketNumber(packetNumber);
        payload.setTotalPackets(numPackets);
        payload.setFileName(filePath);

        if (packetNumber == numPackets) { // last packet
            std::vector<char> messageContent(encryptedFile.begin() + (packetNumber - 1) * messageContentSize, encryptedFile.end());
			int size = messageContent.size();
            payload.setContent(messageContent);
        }
        else { // not last packet (middle or first packet
            std::vector<char> messageContent(encryptedFile.begin() + (packetNumber - 1) * messageContentSize, encryptedFile.begin() + packetNumber * messageContentSize);
            int size = messageContent.size();
            payload.setContent(messageContent);
        }


        // create header request
        std::string clientID = FileHandler::getSpecificLine(Constants::ME_FILE, Constants::ME_CLIENT_ID_LINE);
        RequestHeader header(clientID, Constants::VERSION, RequestHeader::Code::SendFileCode, payload.size());
        // create request
        Request request(header, payload);
        // send request
        sendRequest(request);	
    }   
	// Receive the final response - contains the CRC

	std::cout << std::string(80, '-') << "\nFile sent. Waiting for the server to calculate the CRC...\n" << std::string(80, '-') << std::endl;

    ResponseHeader finalResponseHeader = receiveResponseHeader();
	std::cout << finalResponseHeader.toString() << std::endl;
	ResponsePayload responsePayload = receiveResponsePayload(finalResponseHeader); // 
	std::cout << responsePayload << std::endl;

    if (finalResponseHeader.getCode() == ResponseHeader::Code::FileReceived) {
        try {
            unsigned long result = std::get<unsigned long>(responsePayload.getField("cksum"));
            return result;
        }
        catch (const std::invalid_argument& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }

    }
	// If the file was not received, return -1
    return -1;
}

ResponsePayload ClientSession::receiveResponsePayload(ResponseHeader responseHeader) {
	// Receive the payload
	std::vector<char> responsePayloadBytes(responseHeader.getPayloadSize());
	boost::asio::read(socket, boost::asio::buffer(responsePayloadBytes, responsePayloadBytes.size()));

	// Create a ResponsePayload object and return it
	return ResponsePayload(responseHeader, responsePayloadBytes);
}





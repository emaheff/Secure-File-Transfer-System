#include "ClientSission.h"

using boost::asio::ip::tcp;
using namespace boost::asio;

/**
 * @brief Constructor that establishes a connection to the server.
 *
 * This constructor uses Boost ASIO to initialize a TCP connection to the server using the specified address and port.
 * @param address The server address.
 * @param port The port to connect to.
 */
ClientSession::ClientSession(const std::string& address, const std::string& port)
    : socket(io_context), resolver(io_context) {
    connectToServer(address, port);
}

/**
 * @brief Sends a reconnection request to the server using stored client credentials.
 *
 * This method retrieves the username and client ID from the local storage (me.info) and sends a reconnection request to the server.
 * If the reconnection is successful, the server's response header is returned.
 * @return The response header from the server.
 */
ResponseHeader ClientSession::reconnect() {
	// get username and clientID from me.info
    std::string userName = FileHandler::getSpecificLine(Constants::ME_FILE, Constants::ME_USERNAME_LINE);
    std::string clientID = FileHandler::getSpecificLine(Constants::ME_FILE, Constants::ME_CLIENT_ID_LINE);

	// create reconnecting request
    Request request = prepareReconnectionRequest(userName, clientID);

	std::cout << std::string(Constants::___, '-') << "\nSending reconnection request to the server...\n" << std::string(Constants::___, '-') << std::endl;
	std::cout << request << std::endl;

    sendRequest(request);

	// receive the response header and return it
    return receiveResponseHeader();    
}

/**
 * @brief Registers a new user with the server.
 *
 * This method sends a registration request to the server with the given username. If registration fails, it retries up to 3 times.
 * @param userName The username to register.
 * @return The response header from the server.
 */
ResponseHeader ClientSession::registerUser(const std::string& userName) {
	// create registration request
    Request request = prepareRegistrationRequest(userName);

	std::cout << std::string(Constants::___, '-') << "\nSending registration request to the server...\n" << std::string(Constants::___, '-') << std::endl;
    std::cout << request << std::endl;

    sendRequest(request);

    ResponseHeader responseHeader = receiveResponseHeader();;

	// Retry registration up to 3 times if it fails
    int counter = 1;
    while (responseHeader.getCode() == ResponseHeader::Code::RegistrationFailure && counter <= 3) {
        request = prepareRegistrationRequest(userName);
        sendRequest(request);
        responseHeader = receiveResponseHeader();
        counter++;
    }
	return responseHeader;    
}

/**
 * @brief Calculates the CRC of the specified local file.
 *
 * This method calculates the CRC value for the file at the specified path using the CRC_Calculator class.
 * @param filePath The path to the file.
 * @return The calculated CRC as an unsigned long.
 */
unsigned long ClientSession::getMyCRC(const std::string& filePath) {
    return CRC_Calculator::readFile(filePath);
}

/**
 * @brief Encrypts a file and sends it to the server, then retrieves the server's CRC.
 *
 * This method encrypts the file at the specified path using the provided AES key, sends the file to the server in packets,
 * and retrieves the CRC calculated by the server.
 * @param filePath The path of the file to send.
 * @param encryptedAESKey The AES key to use for encryption.
 * @return The CRC value calculated by the server.
 */
unsigned long ClientSession::getServerCRC(std::string& filePath, const std::vector<char>& encryptedAESKey, const std::string& clientId) {

	// initialize the payload request as it need to be by the given protocol
    int origFileSize = FileHandler::getFileSize(filePath);
    std::vector<char> encryptedFile = encryptFileWithAES(filePath, encryptedAESKey);
    int encryptedFileSize = encryptedFile.size();
    int messageContentSize = Constants::PACKET_SIZE - Constants::REQUEST_HEADER_SIZE - Constants::CONTENT_SIZE_SIZE - Constants::ORIG_FILE_SIZE_SIZE - Constants::PACKET_NUMBER_SIZE
        - Constants::TOTAL_PACKET_SIZE - Constants::FILE_NAME_SIZE;
    // Calculate the number of packets to send ceiling value
    int numPackets = (encryptedFileSize + messageContentSize - 1) / messageContentSize;


    std::cout << std::string(Constants::___, '-') << "\nSending the file to the server in " << numPackets << " packets...\n" << std::string(Constants::___, '-') << std::endl;


    // Send the file in packets
    for (int packetNumber = 1; packetNumber <= numPackets; packetNumber++) {
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
        RequestHeader header(clientId, Constants::VERSION, RequestHeader::Code::SendFileCode, payload.size());
        // create request
        Request request(header, payload);
        // send request
        sendRequest(request);
    }
    // Receive the final response - contains the CRC

    std::cout << std::string(Constants::___, '-') << "\nFile sent. Waiting for the server to calculate the CRC...\n" << std::string(Constants::___, '-') << std::endl;

    ResponseHeader finalResponseHeader = receiveResponseHeader();
    std::cout << finalResponseHeader << std::endl;
    ResponsePayload responsePayload = receiveResponsePayload(finalResponseHeader); 
    std::cout << responsePayload << std::endl;

	// if the response header is FileReceived, return the CRC
    if (finalResponseHeader.getCode() == ResponseHeader::Code::FileReceived) {
        try {
            unsigned long crc = std::get<unsigned long>(responsePayload.getField("cksum"));
            return crc;
        }
        catch (const std::invalid_argument& e) {
            std::cerr << "Error: " << e.what() << std::endl;
        }

    }
    // If the file was not received, return -1
    return -1;
}

/**
 * @brief Receives the response payload from the server based on the response header.
 *
 * @param responseHeader The response header received from the server.
 * @return The response payload received from the server.
 */
ResponsePayload ClientSession::receiveResponsePayload(const ResponseHeader& responseHeader) {
    // Receive the payload
    std::vector<char> responsePayloadBytes(responseHeader.getPayloadSize());
    boost::asio::read(socket, boost::asio::buffer(responsePayloadBytes, responsePayloadBytes.size()));

    // Create a ResponsePayload object and return it
    ResponsePayload responsePayload(responseHeader.getCode(), responsePayloadBytes);
    return responsePayload;
}

/**
 * @brief Processes the client ID, generates RSA keys, and sends the public key to the server.
 *
 * This method extracts the client ID from the response payload, saves it, generates RSA keys,
 * and sends the public key to the server for further communication.
 * @param responsePayload The payload containing the client ID.
 * @param userName The username associated with the request.
 * @return The response header from the server.
 */
ResponseHeader ClientSession::processClientIDAndSendPublicKey(const ResponsePayload& responsePayload, const std::string& userName) {
    try {
        std::string clientID = std::get<std::string>(responsePayload.getField("client_id"));

        // Save UUID to me.info
        FileHandler::writeToFile(Constants::ME_FILE, userName + "\n" + clientID);

        // generate public and private RSA keys. save the private in priv.key and send the public to the server
        std::string publicKey = generateAndSaveRSAKeys();

		// create public key submission request
        Request publicKeyRequest = preparePublicKeySubmissionRequest(clientID, userName, publicKey);

		std::cout << std::string(Constants::___, '-') << "\nSending public key to the server...\n" << std::string(Constants::___, '-') << std::endl;
        std::cout << publicKeyRequest << std::endl;

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


// private methods

/**
 * @brief Connects to the server using the specified address and port.
 *
 * This method resolves the server's address and port and establishes a TCP connection.
 *
 * @param address The server's IP address.
 * @param port The port to connect to.
 */
void ClientSession::connectToServer(const std::string& address, const std::string& port) {
    boost::asio::connect(socket, resolver.resolve(address, port));
}

/**
 * @brief Prepares a reconnection request with the provided username and client ID.
 *
 * This method constructs a reconnection request with the current user's credentials and prepares it for sending to the server.
 *
 * @param userName The client's username.
 * @param clientID The unique client ID used for reconnection.
 * @return A Request object ready to be sent to the server.
 */
Request ClientSession::prepareReconnectionRequest(const std::string& userName, const std::string& clientID) {
    RequestPayload payload;
	payload.setUserName(userName);
    RequestHeader header(clientID, Constants::VERSION, RequestHeader::Code::ReconnectingCode, payload.size());
	Request request(header, payload);
    return request;
}

/**
 * @brief Prepares a registration request for a new user with the specified username.
 *
 * This method creates a registration request for new users, including a temporary client ID. The request is then ready for sending to the server.
 *
 * @param userName The client's username.
 * @return A Request object ready to be sent to the server.
 */
Request ClientSession::prepareRegistrationRequest(const std::string& userName) {
    std::string tempClientID = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF";
    RequestHeader header(tempClientID, Constants::VERSION, RequestHeader::Code::RegistrationCode, Constants::USERNAME_SIZE);
    RequestPayload payload;
	payload.setUserName(userName);
    Request request(header, payload);
    return request;
}

/**
 * @brief Sends a request to the server via the TCP socket.
 *
 * This method sends a serialized request object over the established TCP connection.
 *
 * @param request The request object to send to the server.
 */
void ClientSession::sendRequest(Request& request) {
    std::vector<char> requestBytes = request.toBytes();
    int size = requestBytes.size();
    boost::asio::write(socket, boost::asio::buffer(requestBytes, size));
}

/**
 * @brief Receives a response header from the server.
 *
 * This method waits for and reads the response header sent by the server.
 *
 * @return The received ResponseHeader object.
 */
ResponseHeader ClientSession::receiveResponseHeader() {
    std::vector<char> responseHeaderBytes(Constants::HEADER_RESPONSE_SIZE);
    boost::asio::read(socket, boost::asio::buffer(responseHeaderBytes, responseHeaderBytes.size()));
    ResponseHeader responseHeader(responseHeaderBytes);
    return responseHeader;
}

/**
 * @brief Generates RSA keys, saves the private key, and returns the public key.
 *
 * This method generates RSA public and private keys, saves the Base64-encoded private key to a file, and returns the public key as a string.
 *
 * @return The generated public key as a string.
 */
std::string ClientSession::generateAndSaveRSAKeys() {
    // Generate RSA keys (private and public)
    RSAPrivateWrapper rsaPrivate;

    // Get the private key as a string
    std::string privateKeyStr = rsaPrivate.getPrivateKey();

    // Encode the private key using Base64
    std::string encodedPrivateKey = Base64Wrapper::encode(privateKeyStr);

    // Save the encoded private key to a file
    FileHandler::writeToBinaryFile(Constants::PRIV_FILE, encodedPrivateKey);

    FileHandler::appendToFile(Constants::ME_FILE, "\n" + encodedPrivateKey);

    // Get the public key from the private wrapper
    std::string publicKey = rsaPrivate.getPublicKey();


    // Return the public key vector
    return publicKey;
}


/**
 * @brief Prepares a request to submit the public key to the server.
 *
 * This method constructs a request with the client ID, username, and public key, ready for submission to the server.
 *
 * @param clientId The client's unique identifier.
 * @param userName The client's username.
 * @param publicKey The public key to send to the server.
 * @return A Request object ready to be sent to the server.
 */
Request ClientSession::preparePublicKeySubmissionRequest(const std::string& clientId, const std::string& userName,  const std::string& publicKey) {
	RequestPayload payload;
	payload.setUserName(userName);
	payload.setPublicKey(publicKey);
	RequestHeader header(clientId, Constants::VERSION, RequestHeader::Code::PublicKeyCode, payload.size());
	Request request(header, payload);
	return request;
}

/**
 * @brief Decrypts the provided AES key using the private RSA key.
 *
 * This method reads the private RSA key from the file, decrypts the provided encrypted AES key, and returns the decrypted key.
 *
 * @param encryptedAESKey The encrypted AES key to decrypt.
 * @return The decrypted AES key as a string.
 */
std::string ClientSession::decryptAESKey(const std::vector<char>& encryptedAESKey) {
    // Read the Base64-encoded private RSA key from priv.key using FileHandler
    std::string encodedPrivateKey = FileHandler::readFromBinaryFile(Constants::PRIV_FILE);

    // Decode the private key from Base64
    std::string privateKeyStr = Base64Wrapper::decode(encodedPrivateKey);

    // Use RSAPrivateWrapper to decrypt the AES key
    RSAPrivateWrapper rsaPrivate(privateKeyStr);
    std::string decryptedAESKeyStr = rsaPrivate.decrypt(encryptedAESKey.data(), encryptedAESKey.size());

    return decryptedAESKeyStr;  // Return the decrypted AES key as a string
}

/**
 * @brief Receives the encrypted AES key from the server.
 *
 * This method reads the response payload from the server, extracts the encrypted AES key, and returns it.
 *
 * @param responseHeader The response header received from the server.
 * @return The encrypted AES key as a vector of chars.
 */
std::vector<char> ClientSession::receiveEncryptedAESKey(const ResponseHeader& responseHeader) {
 

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

/**
 * @brief Encrypts the file content using the provided AES key.
 *
 * This method reads the file content from disk, encrypts it using the decrypted AES key, and returns the encrypted data as a vector of chars.
 *
 * @param filePath The path of the file to encrypt.
 * @param encryptedAESKey The AES key used for encryption.
 * @return A vector of chars containing the encrypted file content.
 */
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

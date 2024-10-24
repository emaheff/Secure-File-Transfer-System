#ifndef CLIENTSESSION_H
#define CLIENTSESSION_H

#include <boost/asio.hpp>
#include <string>
#include <vector>
#include <rsa.h>
#include <osrng.h>
#include <files.h>
#include <base64.h>

#include "Request.h"
#include "ResponseHeader.h"
#include "FileHandler.h"
#include "Constants.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "CRC_Calculator.h"


/**
 * @brief Converts a vector of bytes to a hexadecimal string representation.
 *
 * @param buffer The vector of bytes to convert.
 * @return The hexadecimal string representation of the byte vector.
 */
std::string hexify(const std::vector<char>& buffer);


/**
 * @class ClientSession
 * @brief Manages client-side communication with the server, including reconnection, registration, file encryption, and CRC comparison.
 *
 * The ClientSession class is responsible for establishing a connection to the server, handling user registration and reconnection,
 * encrypting files with AES, and sending requests to the server. It also manages key generation and payload construction for network operations.
 */
class ClientSession {
public:
    /**
     * @brief Constructor that initializes the client session and connects to the server.
     *
     * @param address The server address to connect to.
     * @param port The port to use for the connection.
     */
    ClientSession(const std::string& address, const std::string& port);

    /**
     * @brief Attempts to reconnect to the server using stored credentials.
     *
     * This method retrieves the stored client ID and username and attempts to reconnect to the server.
     * @return The response header from the server.
     */
    ResponseHeader reconnect();

    /**
     * @brief Registers the user with the server if reconnection fails.
     *
     * Sends a registration request to the server using the given username.
     * @param userName The username to register with the server.
     * @return The response header from the server.
     */
    ResponseHeader registerUser(const std::string& userName);

    /**
     * @brief Calculates the CRC of the local file.
     *
     * This method calculates the CRC of the specified local file.
     * @param filePath The path of the file to calculate the CRC for.
     * @return The calculated CRC as an unsigned long.
     */
	unsigned long getMyCRC(const std::string& filePath);

    /**
    * @brief Retrieves the CRC of the file from the server.
    *
    * Encrypts the file with the provided AES key, sends it to the server, and retrieves the CRC calculated by the server.
    * @param filePath The path of the file to send.
    * @param encryptedAesKey The AES key to use for encryption.
    * @return The CRC calculated by the server.
    */
	unsigned long getServerCRC(std::string& filePath, const std::vector<char>& encryptedAesKey, const std::string& clientId);

    /**
     * @brief Receives the response payload from the server.
     *
     * This method reads the response payload from the server and returns it as a ResponsePayload object.
     * @param responseHeader The header of the received response.
     * @return The received response payload.
     */
	ResponsePayload receiveResponsePayload(const ResponseHeader& responseHeader);

    /**
     * @brief Processes the client ID and sends the public key to the server.
     *
     * This method saves the client ID to a file, generates RSA keys, and sends the public key to the server.
     * @param responsePayload The response payload containing the client ID.
     * @param userName The username to associate with the request.
     * @return The response header from the server.
     */
    ResponseHeader processClientIDAndSendPublicKey(const ResponsePayload& responsePayload,const std::string& userName);



private:
    boost::asio::io_context io_context; ///< ASIO context for managing asynchronous network operations.
    boost::asio::ip::tcp::socket socket; ///< TCP socket for communicating with the server.
    boost::asio::ip::tcp::resolver resolver; ///< Resolver for determining the server's address.

    /**
     * @brief Connects to the server at the specified address and port.
     *
     * @param address The server address to connect to.
     * @param port The port to use for the connection.
     */
    void connectToServer(const std::string& address, const std::string& port);

    /**
     * @brief Prepares a reconnection request to be sent to the server.
     *
     * @param userName The username for the reconnection request.
     * @param clientID The client ID for the reconnection request.
     * @return A prepared Request object for the reconnection.
     */
    Request prepareReconnectionRequest(const std::string& userName, const std::string& clientID);

    /**
     * @brief Prepares a registration request to be sent to the server.
     *
     * @param userName The username for the registration request.
     * @return A prepared Request object for the registration.
     */
    Request prepareRegistrationRequest(const std::string& userName);

    /**
     * @brief Sends a request to the server.
     *
     * @param request The request object to send.
     */
    void sendRequest(Request& request);

    /**
     * @brief Receives the response header from the server.
     *
     * @return The received ResponseHeader object.
     */
    ResponseHeader receiveResponseHeader();

    /**
     * @brief Generates RSA keys, saves the private key, and returns the public key.
     *
     * This method generates RSA keys and saves the private key to a file. It returns the public key as a string.
     * @return The generated public key as a string.
     */
    std::string generateAndSaveRSAKeys();

    /**
     * @brief Prepares a public key submission request to be sent to the server.
     *
     * @param clientId The client ID for the request.
     * @param userName The username for the request.
     * @param publicKey The public key to be sent in the request.
     * @return A prepared Request object for the public key submission.
     */
	Request preparePublicKeySubmissionRequest(const std::string& clientId, const std::string& userName, const std::string& publicKey);

    /**
     * @brief Decrypts the provided encrypted AES key using the client's private RSA key.
     *
     * @param encryptedAESKey The encrypted AES key to decrypt.
     * @return The decrypted AES key as a string.
     */
    std::string decryptAESKey(const std::vector<char>& encryptedAESKey);

    /**
     * @brief Receives the encrypted AES key from the server.
     *
     * @param responseHeader The response header from the server.
     * @return The encrypted AES key as a vector of chars.
     */
    std::vector<char> receiveEncryptedAESKey(const ResponseHeader& responseHeader);

    /**
     * @brief Encrypts the file content using AES encryption.
     *
     * This method encrypts the file content using the decrypted AES key.
     * @param filePath The path of the file to encrypt.
     * @param encryptedAESKey The AES key used for encryption.
     * @return A vector of chars containing the encrypted file content.
     */
    std::vector<char> encryptFileWithAES(const std::string& filePath, const std::vector<char>& encryptedAESKey);
};

#endif // CLIENTSESSION_H

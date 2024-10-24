#include <boost/asio.hpp>
#include <iostream>

#include "FileHandler.h"
#include "RequestPayload.h"
#include "Constants.h"
#include "ResponseHeader.h"
#include "ResponsePayload.h"
#include "ClientSission.h"

/**
 * @brief Compares the CRC values of the local file and the file on the server.
 *
 * This function compares the CRC of the local file with the CRC provided by the server
 * after encryption. It retries up to 3 times if the CRCs do not match.
 *
 * @param session The current client session used to communicate with the server.
 * @param filePath The file path to the local file for which the CRC needs to be calculated.
 * @param aesKeyVec The AES key vector used for encryption/decryption.
 * @return true if the CRCs match, false otherwise.
 */
bool compareCRCs(ClientSession& session, std::string& filePath, const std::vector<char>& aesKeyVec, const std::string& clientId) {

	unsigned long myCrc = session.getMyCRC(filePath);
	unsigned long serverCrc = session.getServerCRC(filePath, aesKeyVec, clientId);

	// try up to 3 times to compare CRCs
	int counter = 0;
	while (counter < 4 && myCrc != serverCrc) {
		counter++;
		myCrc = session.getMyCRC(filePath);
		serverCrc = session.getServerCRC(filePath, aesKeyVec, clientId);
	}

	if (counter == 4) {
		std::cerr << std::string(Constants::___, '-') << "\nCRC comparison failed after 3 attempts.\tEnd the program\n" << std::string(Constants::___, '-') << std::endl;
		return false;
	}
	
	std::cout << std::string(Constants::___, '-') << "\nCRC comparison successful.\tEnd the program\n" << std::string(Constants::___, '-') << std::endl;
	return true;
}

/**
 * @brief Registers a new user with the server.
 *
 * This function handles the user registration process with the server.
 *
 * @param session The current client session used to communicate with the server.
 * @param userName The username of the client.
 * @param filePath The file path to the local file for which the CRC needs to be calculated.
 * @return true if registration and CRC comparison are successful, false otherwise.
 */
bool registerNewUser(ClientSession& session, std::string& userName, std::string& filePath) {

	std::cout << std::string(Constants::___, '-') << "\nNo " << Constants::ME_FILE << " file found.\nRegistering as a new user...\n" << std::string(Constants::___, '-') << std::endl;
	// Register the user with the server and receive the response header
	ResponseHeader responseHeader = session.registerUser(userName);
	std::cout << std::string(Constants::___, '-') << "\nReceiving response payload to registration request...\n" << std::string(Constants::___, '-') << std::endl;
	std::cout << responseHeader << std::endl;

	// Receive the response payload
	ResponsePayload responsePayload = session.receiveResponsePayload(responseHeader);
	std::cout << responsePayload << std::endl;

	if (responseHeader.getCode() == ResponseHeader::Code::RegistrationSuccess) {
		// Process the client ID and send the public key send public key request and get the response header
		ResponseHeader publicKeyResponseHeader = session.processClientIDAndSendPublicKey(responsePayload, userName);
		std::cout << publicKeyResponseHeader << std::endl;

		// Receive the response payload
		ResponsePayload publicKeyResponsePayload = session.receiveResponsePayload(publicKeyResponseHeader);
		std::cout << publicKeyResponsePayload << std::endl;

		// get the aes key from the response payload and use it to compare CRCs
		auto aesKey = publicKeyResponsePayload.getField("aes_key");
		std::string aes_key_str = std::get<std::string>(aesKey);
		std::vector<char> aesKeyVec(aes_key_str.begin(), aes_key_str.end());

		std::string clientId = std::get<std::string>(responsePayload.getField("client_id"));

		return compareCRCs(session, filePath, aesKeyVec, clientId);
	}
	std::cerr << "Registration failed.\nEnd the program" << std::endl;
	return false;
}

/**
 * @brief Reconnects the client to the server.
 *
 * This function handles the reconnection process of the client to the server.
 *
 * @param session The current client session used to communicate with the server.
 * @param filePath The file path to the local file for which the CRC needs to be calculated.
 * @return true if reconnection and CRC comparison are successful, false otherwise.
 */
bool reconnectToServer(ClientSession& session, std::string& filePath) {

	std::cout << std::string(Constants::___, '-') << "\nReconnecting to the server...\n" << std::string(Constants::___, '-') << std::endl;
	// Reconnect to the server and receive the response header
	ResponseHeader responseHeader = session.reconnect();
	std::cout << std::string(Constants::___, '-') << "\nReceiving response payload to reconnecting request...\n" << std::string(Constants::___, '-') << std::endl;
	std::cout << responseHeader << std::endl;

	// Receive the response payload
	ResponsePayload responsePayload = session.receiveResponsePayload(responseHeader);
	std::cout << responsePayload << std::endl;

	if (responseHeader.getCode() == ResponseHeader::Code::ReconnectionSuccess) {

		// get the aes key from the response payload and use it to compare CRCs
		auto aesKey = responsePayload.getField("aes_key");
		std::string aes_key_str = std::get<std::string>(aesKey);
		std::vector<char> aesKeyVec(aes_key_str.begin(), aes_key_str.end());

		std::string clientId = std::get<std::string>(responsePayload.getField("client_id"));

		return compareCRCs(session, filePath, aesKeyVec, clientId);
	}
	std::cerr << std::string(Constants::___, '-') << "Reconnection failed. Trying to register as a new user" << std::string(Constants::___, '-') << std::endl;
	return false;
}

/**
 * @brief Main function to run the client.
 *
 * This function runs the client by either reconnecting to the server or registering as a new user,
 * depending on the existence of the local ME file.
 */
void runClient() {

	// Read the address, port, username, and file path from the transfer file
	std::cout << std::string(Constants::___, '-') << "\nClient started...\n" << std::string(Constants::___, '-') << std::endl;
	std::string address_and_port = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_ADDRESS_AND_PORT_LINE);
	std::string address = address_and_port.substr(0, address_and_port.find(':'));
	std::string port = address_and_port.substr(address_and_port.find(':') + 1);
	std::string user_name = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_USERNAME_LINE);
	std::string file_path = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_FILE_PATH_LINE);

	std::cout << "\nClient details:\nName - " << user_name << "\nFile path - " << file_path << "\nIp address - " << address << "\nPort - " << port << "\n" << std::endl;

	try {
		ClientSession session(address, port);

		if (FileHandler::isFileExist(Constants::ME_FILE)) {
			if (!reconnectToServer(session, file_path)) {
				registerNewUser(session, user_name, file_path);
			}
		}
		else {
			registerNewUser(session, user_name, file_path);
		}
	}
	catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}

/**
 * @brief Main entry point of the client program.
 *
 * Calls the runClient function and returns 0 when the client execution is completed.
 */
int main() {
	runClient();
    return 0;
}

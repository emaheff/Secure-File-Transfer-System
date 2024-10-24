#include <boost/asio.hpp>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>

#include "FileHandler.h"
#include "RequestPayload.h"
#include "RequestHeader.h"
#include "Request.h"
#include "Constants.h"
#include "ResponseHeader.h"
#include "ResponsePayload.h"
#include "ClientSission.h"


void runClient() {
	std::cout << std::string(80, '-') << "\nClient started...\n" << std::string(80, '-') << std::endl;
	std::string addressAndPort = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_ADDRESS_AND_PORT_LINE);
	std::string address = addressAndPort.substr(0, addressAndPort.find(':'));
	std::string port = addressAndPort.substr(addressAndPort.find(':') + 1);
	std::string userName = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_USERNAME_LINE);
	std::string filePath = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_FILE_PATH_LINE);

	std::cout << "\nClient details:\nName - " << userName << "\nfile path - " << filePath << "\nIp address - " << address << "\nPort - " << port << "\n" << std::endl;

	try {
		ClientSession session(address, port);

		if (FileHandler::isFileExist(Constants::ME_FILE)) {

			// if the file me exists, then try to reconnect to the server. the method returns the response header
			// send 827 request and receive 1605 response if the reconnection is successful and 1606 response if the reconnection is failed
			std::cout << std::string(80, '-') << "\nReconnecting to the server...\n" << std::string(80, '-') << std::endl;
			ResponseHeader responseHeader = session.reconnect();

			std::cout << std::string(80, '-') << "\nReceived response from the server to reconnection request...\n" << std::string(80, '-') << std::endl;

			std::cout << responseHeader.toString() << std::endl;

			// receive the response payload
			ResponsePayload responsePayload = session.receiveResponsePayload(responseHeader);

			// print the response payload
			std::cout << responsePayload.toString() << std::endl;

			// if the response code is RECONNECTION_SUCCESS
			if (responseHeader.getCode() == ResponseHeader::Code::ReconnectionSuccess) {

				// get the aes key from the response payload
				auto aesKey = responsePayload.getField("aes_key");
				// convert it to string from auto type
				std::string aesKeyStr = std::get<std::string>(aesKey);
				// convert it to vector of char
				std::vector<char> aesKeyVec(aesKeyStr.begin(), aesKeyStr.end());

				// compare the CRCs of the file
				unsigned long serverCRC = session.getServerCRC(filePath, aesKeyVec);
				unsigned long myCRC = session.getMyCRC(filePath);
				if (myCRC == serverCRC) {
					std::cout << std::string(80, '-') << "\nCRC comparison successful.\tEnd the program\n" << std::string(80, '-') << std::endl;
					return;
				}
				int counter = 0;
				while (counter < 4 && myCRC != serverCRC) {
					counter++;
					myCRC = session.getMyCRC(filePath);
					serverCRC = session.getServerCRC(filePath, aesKeyVec);
				}
				if (counter == 4) {
					std::cerr << "CRC comparison failed after 3 attempts.\tEnd the program" << std::endl;
					return;
				}
			}
			else {
				std::cerr << "Reconnection failed. Trying to register as a new user" << std::endl;
			}
		}
		else { // if the file me does not exist
			// register to the server - 825 request and get response 1600 if the registration is successful
			// 1601 if the registration is failed

			std::cout << std::string(80, '-') << "\nNo " << Constants::ME_FILE << " file found.\nRegistering as a new user...\n" << std::string(80, '-') << std::endl;

			ResponseHeader responseHeader = session.registerUser(userName);

			std::cout << std::string(80, '-') << "\nReceived response from the server to registration request...\n" << std::string(80, '-') << std::endl;

			std::cout << responseHeader.toString() << std::endl;
			ResponsePayload responsePayload = session.receiveResponsePayload(responseHeader);
			std::cout << responsePayload.toString() << std::endl;

			if (responseHeader.getCode() == ResponseHeader::Code::RegistrationSuccess) {
				ResponseHeader responseHeader = session.processClientIDAndSendPublicKey(responsePayload, userName);

				std::cout << std::string(80, '-') << "\nReceived response from the server to public key request...\n" << std::string(80, '-') << std::endl;

				std::cout << responseHeader.toString() << std::endl;
				ResponsePayload responsePayload = session.receiveResponsePayload(responseHeader);
				std::cout << responsePayload.toString() << std::endl;


				auto aesKey = responsePayload.getField("aes_key");
				std::string aesKeyStr = std::get<std::string>(aesKey);
				// convert it to vector of char
				std::vector<char> aesKeyVec(aesKeyStr.begin(), aesKeyStr.end());


				if (responseHeader.getCode() == ResponseHeader::Code::PublicKeyReceived) {
					unsigned long myCRC = session.getMyCRC(filePath);
					unsigned long serverCRC = session.getServerCRC(filePath, aesKeyVec);
					if (myCRC == serverCRC) {
						std::cout << std::string(80, '-') << "\nCRC comparison successful.\tEnd the program\n" << std::string(80, '-') << std::endl;
						return;
					}
					int counter = 0;
					while (counter < 4 && myCRC != serverCRC) {
						counter++;
						myCRC = session.getMyCRC(filePath);
						serverCRC = session.getServerCRC(filePath, aesKeyVec);
					}
					if (counter == 4) {
						std::cerr << "CRC comparison failed after 3 attempts." << std::endl;
						return;
					}
				}
			}
			else {
				std::cerr << "Registration failed. End the program" << std::endl;
				return;
			}
		}
	}
	catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}
}


int main() {
	runClient();
    return 0;
}

#include <boost/asio.hpp>
#include <iostream>
#include <fstream>

#include "FileHandler.h"
#include "RequestPayload.h"
#include "RequestHeader.h"
#include "Request.h"
#include "Constants.h"
#include "ResponseHeader.h"





using boost::asio::ip::tcp;

int main() {

	std::string addressAndPort = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_ADDRESS_AND_PORT_LINE);
	std::string address = addressAndPort.substr(0, addressAndPort.find(':'));
	std::string port = addressAndPort.substr(addressAndPort.find(':') + 1);
	std::string userName = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_USERNAME_LINE);
	std::string filePath = FileHandler::getSpecificLine(Constants::TRANSFER_FILE, Constants::INFO_FILE_PATH_LINE);

	try {
		boost::asio::io_context io_context;

		tcp::socket socket(io_context);
		tcp::resolver resolver(io_context);
		boost::asio::connect(socket, resolver.resolve(address, port));

		if (FileHandler::isFileExist(Constants::ME_FILE)) {
			userName = FileHandler::getSpecificLine(Constants::ME_FILE, 1);

			// Ensure that the userName does not exceed 254 characters (leaving space for null terminator)
			if (userName.size() > Constants::MAX_USERNAME_LENGTH) {
				//TODO: throw an exception;
			}

			RequestPayload payload;
			std::vector<char> userNameField = payload.stringToFixedSizeVector(userName, Constants::MAX_USERNAME_LENGTH + 1);
			payload.addToPayload(userNameField);

			std::string clientID = FileHandler::getSpecificLine(Constants::ME_FILE, Constants::ME_CLIENT_ID_LINE);
			RequestHeader header(clientID, RequestHeader::VERSION, RequestHeader::Code::ReconnectingCode, payload.size());
			Request request(header, payload);
			std::vector<char> requestBytes = request.toBytes();

			boost::asio::write(socket, boost::asio::buffer(requestBytes, requestBytes.size()));

			// Wait for server response
			std::vector<char> responseHeaderBytes(Constants::HEADER_RESPONSE_SIZE);
			boost::asio::read(socket, boost::asio::buffer(responseHeaderBytes, responseHeaderBytes.size()));

			ResponseHeader responseHeader(responseHeaderBytes);

			if (responseHeader.getCode() == ResponseHeader::Code::ReconnectionFailure) {
				// If reconnect is unsuccessful (server responds with 1606):
			   // TODO: Proceed to User Registration (Step 3)
			}
			else if (responseHeader.getCode() == ResponseHeader::Code::ReconnectionSuccess) {
				// If reconnect is successful (server responds with 1605):
				// Wait for payload (AES key)
				std::vector<char> responsePayloadBytes(responseHeader.getPayloadSize());
				boost::asio::read(socket, boost::asio::buffer(responsePayloadBytes, responsePayloadBytes.size()));
				// TODO: Proceed to File Encryption and Transmission (Step 5)
			}

		}
		else {
			// TODO: Proceed to User Registration (Step 3)
		}
	}
	catch (std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	return 0;
}
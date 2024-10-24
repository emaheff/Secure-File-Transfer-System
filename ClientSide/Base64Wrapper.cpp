#include "Base64Wrapper.h"

/**
 * @brief Encodes the input string into Base64 format.
 *
 * This method takes a standard string as input and uses Crypto++'s Base64Encoder
 * to return the Base64-encoded version of that string. The encoded string is stored in
 * a StringSink, which captures the output of the encoder.
 *
 * @param str The input string to encode.
 * @return A Base64-encoded version of the input string.
 */
std::string Base64Wrapper::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

/**
 * @brief Decodes a Base64-encoded string back into its original form.
 *
 * This method takes a Base64-encoded string and uses Crypto++'s Base64Decoder to
 * decode the string. The decoded output is captured by a StringSink and returned.
 *
 * @param str The Base64-encoded string to decode.
 * @return The decoded original string.
 */
std::string Base64Wrapper::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}

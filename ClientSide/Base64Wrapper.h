#pragma once

#include <string>
#include <base64.h>

/**
 * @class Base64Wrapper
 * @brief This class provides Base64 encoding and decoding functionality.
 *
 * The Base64Wrapper class offers two static methods for encoding strings to Base64 format and decoding
 * Base64-encoded strings back to their original form.
 */
class Base64Wrapper
{
public:

    /**
     * @brief Encodes the input string into Base64 format.
     *
     * This method takes a standard string as input and returns a Base64-encoded version of that string.
     * It uses Crypto++'s Base64Encoder to perform the encoding.
     *
     * @param str The input string to encode.
     * @return A Base64-encoded version of the input string.
     */
	static std::string encode(const std::string& str);

    /**
     * @brief Decodes a Base64-encoded string back into its original form.
     *
     * This method takes a Base64-encoded string as input and returns the decoded version of that string.
     * It uses Crypto++'s Base64Decoder to perform the decoding.
     *
     * @param str The Base64-encoded string to decode.
     * @return The decoded original string.
     */
	static std::string decode(const std::string& str);
};

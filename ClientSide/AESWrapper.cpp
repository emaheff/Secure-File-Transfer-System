#include "AESWrapper.h"
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <stdexcept>
#include <immintrin.h>


/**
 * @brief Generates a random AES key using the Intel rdrand instruction.
 *
 * This function generates a random key of the specified length using the Intel rdrand instruction and stores
 * the generated key in the provided buffer.
 *
 * @param buffer Pointer to a buffer where the generated key will be stored.
 * @param length Length of the key to generate.
 * @return A pointer to the generated key.
 */
unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

/**
 * @brief Default constructor that generates a random 256-bit AES key.
 */
AESWrapper::AESWrapper()
{
	GenerateKey(_key, DEFAULT_KEYLENGTH);
}

/**
 * @brief Constructor that initializes the AESWrapper with a provided key.
 *
 * The provided key must be 32 bytes in length, otherwise a std::length_error is thrown.
 *
 * @param key Pointer to the key used for encryption and decryption.
 * @param length Size of the provided key in bytes.
 * @throws std::length_error if the key length is not 32 bytes.
 */
AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (length != DEFAULT_KEYLENGTH)
		throw std::length_error("key length must be 32 bytes");
	memcpy_s(_key, DEFAULT_KEYLENGTH, key, length);
}

/**
 * @brief Destructor for the AESWrapper class.
 */
AESWrapper::~AESWrapper()
{
}

/**
 * @brief Retrieves the current AES key used by the AESWrapper.
 *
 * @return A pointer to the AES key.
 */
const unsigned char* AESWrapper::getKey() const 
{ 
	return _key; 
}

/**
 * @brief Encrypts the provided plaintext data using AES-CBC encryption.
 *
 * The encryption is performed in AES-CBC mode with a zero initialization vector (IV).
 * @param plain Pointer to the plaintext data to encrypt.
 * @param length Length of the plaintext data in bytes.
 * @return A string containing the encrypted data (ciphertext).
 */
std::string AESWrapper::encrypt(const char* plain, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Encryption aesEncryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}

/**
 * @brief Decrypts the provided ciphertext data using AES-CBC decryption.
 *
 * The decryption is performed in AES-CBC mode with a zero initialization vector (IV).
 * @param cipher Pointer to the encrypted data (ciphertext) to decrypt.
 * @param length Length of the ciphertext data in bytes.
 * @return A string containing the decrypted plaintext.
 */
std::string AESWrapper::decrypt(const char* cipher, unsigned int length)
{
	CryptoPP::byte iv[CryptoPP::AES::BLOCKSIZE] = { 0 };	// for practical use iv should never be a fixed value!

	CryptoPP::AES::Decryption aesDecryption(_key, DEFAULT_KEYLENGTH);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}

#pragma once

#include <string>

/**
 * @class AESWrapper
 * @brief This class provides AES encryption and decryption functionality using a symmetric key.
 *
 * The AESWrapper class offers methods to generate a 256-bit AES key, encrypt and decrypt data using AES in CBC mode,
 * and retrieve the key. The default key length used in this class is 256 bits (32 bytes).
 */


class AESWrapper
{
public:

	/**
	 * @brief Default key length (256 bits, or 32 bytes) for AES encryption.
	 */
	static const unsigned int DEFAULT_KEYLENGTH = 32;
private:

	/**
	 * @brief AES key used for encryption and decryption.
	 */
	unsigned char _key[DEFAULT_KEYLENGTH];
	AESWrapper(const AESWrapper& aes);


public:
	/**
	 * @brief Generates a random AES key and stores it in the provided buffer.
	 *
	 * @param buffer Pointer to a buffer where the generated key will be stored.
	 * @param length Length of the key to generate.
	 * @return A pointer to the generated key.
	 */
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);

	/**
	 * @brief Default constructor that generates a new random AES key of DEFAULT_KEYLENGTH.
	 */
	AESWrapper();

	/**
	 * @brief Constructor that initializes the AESWrapper with a provided key.
	 *
	 * @param key Pointer to a key used for encryption and decryption.
	 * @param size Size of the provided key. Must be DEFAULT_KEYLENGTH.
	 * @throws std::length_error if the key length is not 32 bytes.
	 */
	AESWrapper(const unsigned char* key, unsigned int size);

	/**
	 * @brief Destructor.
	 */
	~AESWrapper();

	/**
	* @brief Retrieves the current AES key used by the AESWrapper.
	*
	* @return A pointer to the AES key.
	*/
	const unsigned char* getKey() const;

	/**
	 * @brief Encrypts the provided plaintext data using AES encryption.
	 *
	 * The encryption is performed in AES-CBC mode.
	 * @param plain Pointer to the plaintext data to encrypt.
	 * @param length Length of the plaintext data in bytes.
	 * @return A string containing the encrypted data (ciphertext).
	 */
	std::string encrypt(const char* plain, unsigned int length);

	/**
	 * @brief Decrypts the provided ciphertext data using AES decryption.
	 *
	 * The decryption is performed in AES-CBC mode.
	 * @param cipher Pointer to the encrypted data (ciphertext) to decrypt.
	 * @param length Length of the ciphertext data in bytes.
	 * @return A string containing the decrypted plaintext.
	 */
	std::string decrypt(const char* cipher, unsigned int length);
};
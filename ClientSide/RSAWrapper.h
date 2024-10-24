#pragma once

#include <osrng.h>
#include <rsa.h>
#include <string>


/**
 * @class RSAPublicWrapper
 * @brief A wrapper class for handling RSA public key operations.
 *
 * The RSAPublicWrapper class provides functionality for managing RSA public keys, including loading keys,
 * encrypting data, and retrieving public keys as strings or in a byte array format.
 */
class RSAPublicWrapper
{
public:
	static const unsigned int KEYSIZE = 160;   ///< The key size in bytes for the RSA public key.
	static const unsigned int BITS = 1024;     ///< The bit size of the RSA key.

private:
	CryptoPP::AutoSeededRandomPool _rng;      ///< Random number generator used for RSA operations.
	CryptoPP::RSA::PublicKey _publicKey;      ///< The RSA public key object.

	// Private copy constructor and assignment operator to prevent copying
	RSAPublicWrapper(const RSAPublicWrapper& rsapublic);
	RSAPublicWrapper& operator=(const RSAPublicWrapper& rsapublic);
public:
	/**
	 * @brief Constructs an RSAPublicWrapper from a key in byte format.
	 * @param key The public key as a byte array.
	 * @param length The length of the key in bytes.
	 */
	RSAPublicWrapper(const char* key, unsigned int length);

	/**
	 * @brief Constructs an RSAPublicWrapper from a key in string format.
	 * @param key The public key as a string.
	 */
	RSAPublicWrapper(const std::string& key);

	/**
	 * @brief Destructor for RSAPublicWrapper.
	 */
	~RSAPublicWrapper();

	/**
	 * @brief Retrieves the public key as a string.
	 * @return The public key as a string.
	 */
	std::string getPublicKey() const;

	/**
	 * @brief Retrieves the public key and writes it into a provided buffer.
	 * @param keyout The output buffer where the key will be written.
	 * @param length The length of the output buffer.
	 * @return A pointer to the output buffer.
	 */
	char* getPublicKey(char* keyout, unsigned int length) const;

	/**
	 * @brief Encrypts a plaintext string using the RSA public key.
	 * @param plain The plaintext string to be encrypted.
	 * @return The encrypted string (ciphertext).
	 */
	std::string encrypt(const std::string& plain);

	/**
	 * @brief Encrypts a plaintext byte array using the RSA public key.
	 * @param plain The plaintext byte array to be encrypted.
	 * @param length The length of the plaintext byte array.
	 * @return The encrypted string (ciphertext).
	 */
	std::string encrypt(const char* plain, unsigned int length);
};


/**
 * @class RSAPrivateWrapper
 * @brief A wrapper class for handling RSA private key operations.
 *
 * The RSAPrivateWrapper class provides functionality for managing RSA private keys, including generating keys,
 * decrypting data, and retrieving both private and public keys as strings or in byte array format.
 */
class RSAPrivateWrapper
{
public:
	static const unsigned int BITS = 1024;    ///< The bit size of the RSA key.

private:
	CryptoPP::AutoSeededRandomPool _rng;      ///< Random number generator used for RSA operations.
	CryptoPP::RSA::PrivateKey _privateKey;    ///< The RSA private key object.

	// Private copy constructor and assignment operator to prevent copying
	RSAPrivateWrapper(const RSAPrivateWrapper& rsaprivate);
	RSAPrivateWrapper& operator=(const RSAPrivateWrapper& rsaprivate);
public:
	/**
	 * @brief Constructs a new RSA private key wrapper and generates a new private key.
	 */
	RSAPrivateWrapper();

	/**
	 * @brief Constructs an RSAPrivateWrapper from a key in byte format.
	 * @param key The private key as a byte array.
	 * @param length The length of the key in bytes.
	 */
	RSAPrivateWrapper(const char* key, unsigned int length);

	/**
	 * @brief Constructs an RSAPrivateWrapper from a key in string format.
	 * @param key The private key as a string.
	 */
	RSAPrivateWrapper(const std::string& key);

	/**
	 * @brief Destructor for RSAPrivateWrapper.
	 */
	~RSAPrivateWrapper();

	/**
	 * @brief Retrieves the private key as a string.
	 * @return The private key as a string.
	 */
	std::string getPrivateKey() const;

	/**
	 * @brief Retrieves the private key and writes it into a provided buffer.
	 * @param keyout The output buffer where the key will be written.
	 * @param length The length of the output buffer.
	 * @return A pointer to the output buffer.
	 */
	char* getPrivateKey(char* keyout, unsigned int length) const;

	/**
	 * @brief Retrieves the public key corresponding to the private key as a string.
	 * @return The public key as a string.
	 */
	std::string getPublicKey() const;

	/**
	 * @brief Retrieves the public key corresponding to the private key and writes it into a provided buffer.
	 * @param keyout The output buffer where the key will be written.
	 * @param length The length of the output buffer.
	 * @return A pointer to the output buffer.
	 */
	char* getPublicKey(char* keyout, unsigned int length) const;

	/**
	 * @brief Decrypts a ciphertext string using the RSA private key.
	 * @param cipher The ciphertext string to be decrypted.
	 * @return The decrypted string (plaintext).
	 */
	std::string decrypt(const std::string& cipher);

	/**
	 * @brief Decrypts a ciphertext byte array using the RSA private key.
	 * @param cipher The ciphertext byte array to be decrypted.
	 * @param length The length of the ciphertext byte array.
	 * @return The decrypted string (plaintext).
	 */
	std::string decrypt(const char* cipher, unsigned int length);
};

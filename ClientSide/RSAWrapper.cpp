#include "RSAWrapper.h"

/**
 * @brief Constructs an RSAPublicWrapper from a key in byte format.
 *
 * This constructor initializes the RSA public key from the provided byte array.
 *
 * @param key The public key as a byte array.
 * @param length The length of the key in bytes.
 */
RSAPublicWrapper::RSAPublicWrapper(const char* key, unsigned int length)
{
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	_publicKey.Load(ss);
}

/**
 * @brief Constructs an RSAPublicWrapper from a key in string format.
 *
 * This constructor initializes the RSA public key from the provided string.
 *
 * @param key The public key as a string.
 */
RSAPublicWrapper::RSAPublicWrapper(const std::string& key)
{
	CryptoPP::StringSource ss(key, true);
	_publicKey.Load(ss);
}

/**
 * @brief Destructor for RSAPublicWrapper.
 */
RSAPublicWrapper::~RSAPublicWrapper()
{
}

/**
 * @brief Retrieves the public key as a string.
 *
 * This method returns the public key as a string.
 *
 * @return The public key as a string.
 */
std::string RSAPublicWrapper::getPublicKey() const
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_publicKey.Save(ss);
	return key;
}

/**
 * @brief Retrieves the public key and writes it into a provided buffer.
 *
 * This method writes the public key into a buffer provided by the caller.
 *
 * @param keyout The output buffer where the key will be written.
 * @param length The length of the output buffer.
 * @return A pointer to the output buffer.
 */
char* RSAPublicWrapper::getPublicKey(char* keyout, unsigned int length) const
{
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_publicKey.Save(as);
	return keyout;
}

/**
 * @brief Encrypts a plaintext string using the RSA public key.
 *
 * This method encrypts the given plaintext string using the RSA public key.
 *
 * @param plain The plaintext string to be encrypted.
 * @return The encrypted string (ciphertext).
 */
std::string RSAPublicWrapper::encrypt(const std::string& plain)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(plain, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}

	/**
	 * @brief Encrypts a plaintext byte array using the RSA public key.
	 * @param plain The plaintext byte array to be encrypted.
	 * @param length The length of the plaintext byte array.
	 * @return The encrypted string (ciphertext).
	 */
std::string RSAPublicWrapper::encrypt(const char* plain, unsigned int length)
{
	std::string cipher;
	CryptoPP::RSAES_OAEP_SHA_Encryptor e(_publicKey);
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(plain), length, true, new CryptoPP::PK_EncryptorFilter(_rng, e, new CryptoPP::StringSink(cipher)));
	return cipher;
}


/**
 * @brief Constructs a new RSA private key wrapper and generates a new private key.
 */
RSAPrivateWrapper::RSAPrivateWrapper()
{
	_privateKey.Initialize(_rng, BITS);
}

/**
 * @brief Constructs an RSAPrivateWrapper from a key in byte format.
 * @param key The private key as a byte array.
 * @param length The length of the key in bytes.
 */
RSAPrivateWrapper::RSAPrivateWrapper(const char* key, unsigned int length)
{
	CryptoPP::StringSource ss(reinterpret_cast<const CryptoPP::byte*>(key), length, true);
	_privateKey.Load(ss);
}

/**
 * @brief Constructs an RSAPrivateWrapper from a key in string format.
 * @param key The private key as a string.
 */
RSAPrivateWrapper::RSAPrivateWrapper(const std::string& key)
{
	CryptoPP::StringSource ss(key, true);
	_privateKey.Load(ss);
}

/**
 * @brief Destructor for RSAPrivateWrapper.
 */
RSAPrivateWrapper::~RSAPrivateWrapper()
{
}

/**
 * @brief Retrieves the private key as a string.
 * @return The private key as a string.
 */
std::string RSAPrivateWrapper::getPrivateKey() const
{
	std::string key;
	CryptoPP::StringSink ss(key);
	_privateKey.Save(ss);
	return key;
}

/**
 * @brief Retrieves the private key and writes it into a provided buffer.
 * @param keyout The output buffer where the key will be written.
 * @param length The length of the output buffer.
 * @return A pointer to the output buffer.
 */
char* RSAPrivateWrapper::getPrivateKey(char* keyout, unsigned int length) const
{
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	_privateKey.Save(as);
	return keyout;
}

/**
 * @brief Retrieves the public key corresponding to the private key as a string.
 * @return The public key as a string.
 */
std::string RSAPrivateWrapper::getPublicKey() const
{
	CryptoPP::RSAFunction publicKey(_privateKey);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	return key;
}

/**
 * @brief Retrieves the public key corresponding to the private key and writes it into a provided buffer.
 * @param keyout The output buffer where the key will be written.
 * @param length The length of the output buffer.
 * @return A pointer to the output buffer.
 */
char* RSAPrivateWrapper::getPublicKey(char* keyout, unsigned int length) const
{
	CryptoPP::RSAFunction publicKey(_privateKey);
	CryptoPP::ArraySink as(reinterpret_cast<CryptoPP::byte*>(keyout), length);
	publicKey.Save(as);
	return keyout;
}

/**
 * @brief Decrypts a ciphertext string using the RSA private key.
 * @param cipher The ciphertext string to be decrypted.
 * @return The decrypted string (plaintext).
 */
std::string RSAPrivateWrapper::decrypt(const std::string& cipher)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(cipher, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}

/**
 * @brief Decrypts a ciphertext byte array using the RSA private key.
 * @param cipher The ciphertext byte array to be decrypted.
 * @param length The length of the ciphertext byte array.
 * @return The decrypted string (plaintext).
 */
std::string RSAPrivateWrapper::decrypt(const char* cipher, unsigned int length)
{
	std::string decrypted;
	CryptoPP::RSAES_OAEP_SHA_Decryptor d(_privateKey);
	CryptoPP::StringSource ss_cipher(reinterpret_cast<const CryptoPP::byte*>(cipher), length, true, new CryptoPP::PK_DecryptorFilter(_rng, d, new CryptoPP::StringSink(decrypted)));
	return decrypted;
}

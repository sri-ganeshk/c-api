#include <iostream>
#include <string>
#include <stdexcept>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <secblock.h>
#include <base64.h>

using namespace CryptoPP;

// Function to encrypt plaintext using AES-CBC and return a Base64-encoded ciphertext
std::string encryptPassword(const std::string& plaintext, const std::string& key, const std::string& iv) {
    try {
        // Ensure key and IV lengths are correct for AES-128
        if (key.size() != AES::DEFAULT_KEYLENGTH) {
            throw std::invalid_argument("Invalid key length. Key must be 16 bytes for AES-128.");
        }
        if (iv.size() != AES::BLOCKSIZE) {
            throw std::invalid_argument("Invalid IV length. IV must be 16 bytes.");
        }

        // // Padding the plaintext to match AES block size (PKCS7 padding)
        // std::string paddedPlaintext = plaintext;
        // size_t padding = AES::BLOCKSIZE - (plaintext.size() % AES::BLOCKSIZE);
        // paddedPlaintext.append(padding, static_cast<char>(padding));

        std::string encrypted;

        // Encrypt using AES in CBC mode
        CBC_Mode<AES>::Encryption encryption;
        encryption.SetKeyWithIV((byte*)key.data(), key.size(), (byte*)iv.data());

        StringSource(paddedPlaintext, true,
            new StreamTransformationFilter(encryption,
                new StringSink(encrypted)
            )
        );

        // Encode encrypted bytes to Base64
        std::string encryptedBase64;
        StringSource(encrypted, true,
            new Base64Encoder(
                new StringSink(encryptedBase64), false // Do not add line breaks
            )
        );

        return encryptedBase64;
    } catch (const Exception& e) {
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
        return "";
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return "";
    }
}

int main() {
    // Example inputs
    std::string plaintext = "Gan@2004";
    std::string key = "8701661282118308";  // 16-byte key
    std::string iv = "8701661282118308";  // 16-byte IV

    // Encrypt the plaintext
    std::string encrypted = encryptPassword(plaintext, key, iv);

    // Display the encrypted text
    if (!encrypted.empty()) {
        std::cout << "Encrypted (Base64): " << encrypted << std::endl;
    } else {
        std::cerr << "Encryption failed." << std::endl;
    }

    return 0;
}

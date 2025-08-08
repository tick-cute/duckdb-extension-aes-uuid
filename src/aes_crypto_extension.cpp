#define DUCKDB_EXTENSION_MAIN

#include "aes_crypto_extension.hpp"
#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension_util.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

// OpenSSL linked through vcpkg
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>

namespace duckdb {

// Helper function to convert hex string to bytes
static std::vector<uint8_t> HexToBytes(const std::string &hex) {
	std::vector<uint8_t> bytes;
	for (size_t i = 0; i < hex.length(); i += 2) {
		std::string byteString = hex.substr(i, 2);
		uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
		bytes.push_back(byte);
	}
	return bytes;
}

// Helper function to convert bytes to hex string
static std::string BytesToHex(const std::vector<uint8_t> &bytes) {
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (uint8_t byte : bytes) {
		ss << std::setw(2) << static_cast<int>(byte);
	}
	return ss.str();
}

// Helper function to format hex as UUID
static std::string FormatAsUUID(const std::string &hex) {
	if (hex.length() == 32) {
		return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" +
		       hex.substr(20, 12);
	} else if (hex.length() == 64) {
		// For 32-byte data, create two UUIDs separated by a dash
		return hex.substr(0, 8) + "-" + hex.substr(8, 4) + "-" + hex.substr(12, 4) + "-" + hex.substr(16, 4) + "-" +
		       hex.substr(20, 12) + "-" + hex.substr(32, 8) + "-" + hex.substr(40, 4) + "-" + hex.substr(44, 4) + "-" +
		       hex.substr(48, 4) + "-" + hex.substr(52, 12);
	}
	return hex; // Return as-is if not standard length
}

// AES-256-ECB Encryption Function
inline void AesEncryptFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &namespace_vector = args.data[0];
	auto &id_vector = args.data[1];
	auto &key_vector = args.data[2];

	TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
	    namespace_vector, id_vector, key_vector, result, args.size(),
	    [&](string_t namespace_hex, string_t id_hex, string_t key_hex) {
		    try {
			    // Convert inputs
			    std::string ns_str = namespace_hex.GetString();
			    std::string id_str = id_hex.GetString();
			    std::string key_str = key_hex.GetString();

			    // Combine namespace and id
			    std::string combined_hex = ns_str + id_str;
			    auto combined_bytes = HexToBytes(combined_hex);

			    // Check size limits (32 bytes max)
			    if (combined_bytes.size() > 32) {
				    return StringVector::AddString(result, "ERROR:OVERSIZE");
			    }

			    // Validate key (must be 32 bytes for AES-256)
			    auto key_bytes = HexToBytes(key_str);
			    if (key_bytes.size() != 32) {
				    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
			    }

			    // Pad data to 16 or 32 bytes
			    size_t target_size = combined_bytes.size() <= 16 ? 16 : 32;
			    combined_bytes.resize(target_size, 0);

			    // Set up AES encryption
			    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			    if (!ctx) {
				    return StringVector::AddString(result, "ERROR:CTX_CREATION_FAILED");
			    }

			    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPT_INIT_FAILED");
			    }

			    // Disable padding since we handle it manually
			    EVP_CIPHER_CTX_set_padding(ctx, 0);

			    std::vector<uint8_t> encrypted(target_size);
			    int len;

			    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, combined_bytes.data(), target_size) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPT_UPDATE_FAILED");
			    }

			    int final_len;
			    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPT_FINAL_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert to hex and format as UUID
			    std::string encrypted_hex = BytesToHex(encrypted);
			    std::string uuid_formatted = FormatAsUUID(encrypted_hex);

			    return StringVector::AddString(result, uuid_formatted);

		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:ENCRYPTION_FAILED");
		    }
	    });
}

// AES-256-ECB Decryption Function
inline void AesDecryptFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &uuid_vector = args.data[0];
	auto &key_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    uuid_vector, key_vector, result, args.size(), [&](string_t uuid_str, string_t key_hex) {
		    try {
			    std::string uuid = uuid_str.GetString();
			    std::string key_str = key_hex.GetString();

			    // Remove dashes from UUID to get hex
			    std::string encrypted_hex;
			    for (char c : uuid) {
				    if (c != '-') {
					    encrypted_hex += c;
				    }
			    }

			    auto encrypted_bytes = HexToBytes(encrypted_hex);
			    auto key_bytes = HexToBytes(key_str);

			    if (key_bytes.size() != 32) {
				    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
			    }

			    // Set up AES decryption
			    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			    if (!ctx) {
				    return StringVector::AddString(result, "ERROR:CTX_CREATION_FAILED");
			    }

			    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_INIT_FAILED");
			    }

			    EVP_CIPHER_CTX_set_padding(ctx, 0);

			    std::vector<uint8_t> decrypted(encrypted_bytes.size());
			    int len;

			    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted_bytes.data(), encrypted_bytes.size()) !=
			        1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_UPDATE_FAILED");
			    }

			    int final_len;
			    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_FINAL_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert back to hex
			    std::string decrypted_hex = BytesToHex(decrypted);

			    return StringVector::AddString(result, decrypted_hex);

		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:DECRYPTION_FAILED");
		    }
	    });
}

// High-level encode function: encode(namespace_hex, id_hex, key_hex) -> uuid_string
inline void EncodeFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	// This is just a wrapper around AesEncryptFunction for the revid interface
	AesEncryptFunction(args, state, result);
}

// High-level decode function: decode(uuid_string, key_hex) -> struct{namespace, id}
inline void DecodeFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &uuid_vector = args.data[0];
	auto &key_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    uuid_vector, key_vector, result, args.size(), [&](string_t uuid_str, string_t key_hex) {
		    try {
			    std::string uuid = uuid_str.GetString();
			    std::string key_str = key_hex.GetString();

			    // Remove dashes from UUID to get hex
			    std::string encrypted_hex;
			    for (char c : uuid) {
				    if (c != '-') {
					    encrypted_hex += c;
				    }
			    }

			    auto encrypted_bytes = HexToBytes(encrypted_hex);
			    auto key_bytes = HexToBytes(key_str);

			    if (key_bytes.size() != 32) {
				    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
			    }

			    // Set up AES decryption
			    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			    if (!ctx) {
				    return StringVector::AddString(result, "ERROR:CTX_CREATION_FAILED");
			    }

			    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_INIT_FAILED");
			    }

			    EVP_CIPHER_CTX_set_padding(ctx, 0);

			    std::vector<uint8_t> decrypted(encrypted_bytes.size());
			    int len;

			    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted_bytes.data(), encrypted_bytes.size()) !=
			        1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_UPDATE_FAILED");
			    }

			    int final_len;
			    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_FINAL_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert back to hex and format as "namespace:id"
			    std::string decrypted_hex = BytesToHex(decrypted);

			    // For now, return the raw hex - in a real implementation we'd need to
			    // know where the namespace ends and ID begins
			    // This could be improved by storing the namespace length in the first byte
			    return StringVector::AddString(result, decrypted_hex);

		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:DECRYPTION_FAILED");
		    }
	    });
}

// Enhanced encode function that produces standards-compliant UUIDs (namespace_hex + id_hex)
inline void EncodeValidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &namespace_vector = args.data[0];
	auto &id_vector = args.data[1];
	auto &key_vector = args.data[2];

	TernaryExecutor::Execute<string_t, string_t, string_t, string_t>(
	    namespace_vector, id_vector, key_vector, result, args.size(),
	    [&](string_t namespace_hex, string_t id_hex, string_t key_hex) {
		    try {
			    // First encrypt normally using existing logic
			    std::string ns_str = namespace_hex.GetString();
			    std::string id_str = id_hex.GetString();
			    std::string key_str = key_hex.GetString();

			    auto ns_bytes = HexToBytes(ns_str);
			    auto id_bytes = HexToBytes(id_str);
			    std::vector<uint8_t> combined_bytes;
			    combined_bytes.insert(combined_bytes.end(), ns_bytes.begin(), ns_bytes.end());
			    combined_bytes.insert(combined_bytes.end(), id_bytes.begin(), id_bytes.end());

			    if (combined_bytes.size() > 32) {
				    return StringVector::AddString(result, "ERROR:OVERSIZE");
			    }

			    auto key_bytes = HexToBytes(key_str);
			    if (key_bytes.size() != 32) {
				    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
			    }

			    // Pad data to 16 or 32 bytes
			    size_t target_size = combined_bytes.size() <= 16 ? 16 : 32;
			    combined_bytes.resize(target_size, 0);

			    // Encrypt with AES-256-ECB
			    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			    if (!ctx) {
				    return StringVector::AddString(result, "ERROR:CONTEXT_FAILED");
			    }

			    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPT_INIT_FAILED");
			    }

			    EVP_CIPHER_CTX_set_padding(ctx, 0);

			    std::vector<uint8_t> encrypted(target_size);
			    int len;

			    if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, combined_bytes.data(), target_size) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPT_UPDATE_FAILED");
			    }

			    int final_len;
			    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPT_FINAL_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert to hex
			    std::string encrypted_hex = BytesToHex(encrypted);

			    // Now make it a valid UUID by forcing version and variant bits
			    // Extract original version (position 12) and variant (position 16) bits
			    char orig_version = encrypted_hex[12];
			    char orig_variant = encrypted_hex[16];

			    // Create valid UUID v4: force version=4, variant=8,9,A,B (binary 10xx)
			    // Store original bits in safe positions (positions 7 and 17)
			    std::string valid_hex = encrypted_hex;
			    valid_hex[7] = orig_version;  // Store original version at position 7
			    valid_hex[12] = '4';          // Force version 4 (UUID v4)
			    valid_hex[16] = '8';          // Force variant to 8 (binary 1000, valid variant)
			    valid_hex[17] = orig_variant; // Store original variant at position 17

			    // Format as UUID
			    std::string valid_uuid = FormatAsUUID(valid_hex);

			    return StringVector::AddString(result, valid_uuid);

		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:ENCRYPTION_FAILED");
		    }
	    });
}

// Enhanced decode function that handles standards-compliant UUIDs (namespace_hex + id_hex)
inline void DecodeValidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &uuid_vector = args.data[0];
	auto &key_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    uuid_vector, key_vector, result, args.size(), [&](string_t uuid_str, string_t key_hex) {
		    try {
			    std::string uuid = uuid_str.GetString();
			    std::string key_str = key_hex.GetString();

			    // Remove dashes from UUID
			    std::string hex_no_dashes;
			    for (char c : uuid) {
				    if (c != '-') {
					    hex_no_dashes += c;
				    }
			    }

			    // Restore original version and variant bits from hidden positions
			    std::string original_hex = hex_no_dashes;
			    char orig_version = hex_no_dashes[7];  // Retrieve original version from position 7
			    char orig_variant = hex_no_dashes[17]; // Retrieve original variant from position 17

			    original_hex[12] = orig_version; // Restore original version
			    original_hex[16] = orig_variant; // Restore original variant

			    auto encrypted_bytes = HexToBytes(original_hex);
			    auto key_bytes = HexToBytes(key_str);

			    if (key_bytes.size() != 32) {
				    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
			    }

			    // Decrypt with AES-256-ECB
			    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			    if (!ctx) {
				    return StringVector::AddString(result, "ERROR:CONTEXT_FAILED");
			    }

			    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_INIT_FAILED");
			    }

			    EVP_CIPHER_CTX_set_padding(ctx, 0);

			    std::vector<uint8_t> decrypted(encrypted_bytes.size());
			    int len;

			    if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted_bytes.data(), encrypted_bytes.size()) !=
			        1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_UPDATE_FAILED");
			    }

			    int final_len;
			    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPT_FINAL_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert back to hex
			    std::string decrypted_hex = BytesToHex(decrypted);

			    return StringVector::AddString(result, decrypted_hex);

		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:DECRYPTION_FAILED");
		    }
	    });
}

// Enhanced encode function (single payload) that produces standards-compliant UUID v4
// Signature: aes_crypto_encode_valid_uuid(payload_hex, key_hex) -> uuid_v4_string
inline void EncodeValidUuidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &payload_vector = args.data[0];
    auto &key_vector = args.data[1];

    BinaryExecutor::Execute<string_t, string_t, string_t>(
        payload_vector, key_vector, result, args.size(), [&](string_t payload_hex, string_t key_hex) {
            try {
                std::string payload_str = payload_hex.GetString();
                std::string key_str = key_hex.GetString();

                auto payload_bytes = HexToBytes(payload_str);
                if (payload_bytes.size() > 32) {
                    return StringVector::AddString(result, "ERROR:OVERSIZE");
                }

                auto key_bytes = HexToBytes(key_str);
                if (key_bytes.size() != 32) {
                    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
                }

                // Pad data to 16 or 32 bytes
                size_t target_size = payload_bytes.size() <= 16 ? 16 : 32;
                payload_bytes.resize(target_size, 0);

                // Encrypt with AES-256-ECB
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    return StringVector::AddString(result, "ERROR:CONTEXT_FAILED");
                }

                if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:ENCRYPT_INIT_FAILED");
                }

                EVP_CIPHER_CTX_set_padding(ctx, 0);

                std::vector<uint8_t> encrypted(target_size);
                int len;

                if (EVP_EncryptUpdate(ctx, encrypted.data(), &len, payload_bytes.data(), target_size) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:ENCRYPT_UPDATE_FAILED");
                }

                int final_len;
                if (EVP_EncryptFinal_ex(ctx, encrypted.data() + len, &final_len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:ENCRYPT_FINAL_FAILED");
                }

                EVP_CIPHER_CTX_free(ctx);

                // Convert to hex
                std::string encrypted_hex = BytesToHex(encrypted);

                // Force version/variant bits, preserve originals at positions 7 and 17
                char orig_version = encrypted_hex[12];
                char orig_variant = encrypted_hex[16];

                std::string valid_hex = encrypted_hex;
                valid_hex[7] = orig_version;   // store original version
                valid_hex[12] = '4';           // UUID v4
                valid_hex[16] = '8';           // valid variant (1000)
                valid_hex[17] = orig_variant;  // store original variant

                // Format as UUID string
    std::string valid_uuid = FormatAsUUID(valid_hex);
    return StringVector::AddString(result, valid_uuid);

            } catch (...) {
                return StringVector::AddString(result, "ERROR:ENCRYPTION_FAILED");
            }
        });
}

// Enhanced decode function (single payload) that handles standards-compliant UUID v4
// Signature: aes_crypto_decode_valid_uuid(uuid_v4_string, key_hex) -> payload_hex
inline void DecodeValidUuidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
    auto &uuid_vector = args.data[0];
    auto &key_vector = args.data[1];

    BinaryExecutor::Execute<string_t, string_t, string_t>(
        uuid_vector, key_vector, result, args.size(), [&](string_t uuid_str, string_t key_hex) {
            try {
                std::string uuid = uuid_str.GetString();
                std::string key_str = key_hex.GetString();

                // Remove dashes
                std::string hex_no_dashes;
                for (char c : uuid) {
                    if (c != '-') {
                        hex_no_dashes += c;
                    }
                }

                // Restore original version and variant from positions 7 and 17
                std::string original_hex = hex_no_dashes;
                char orig_version = hex_no_dashes[7];
                char orig_variant = hex_no_dashes[17];
                original_hex[12] = orig_version;
                original_hex[16] = orig_variant;

                auto encrypted_bytes = HexToBytes(original_hex);
                auto key_bytes = HexToBytes(key_str);
                if (key_bytes.size() != 32) {
                    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
                }

                // Decrypt
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    return StringVector::AddString(result, "ERROR:CONTEXT_FAILED");
                }
                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:DECRYPT_INIT_FAILED");
                }
                EVP_CIPHER_CTX_set_padding(ctx, 0);

                std::vector<uint8_t> decrypted(encrypted_bytes.size());
                int len;
                if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, encrypted_bytes.data(), encrypted_bytes.size()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:DECRYPT_UPDATE_FAILED");
                }
                int final_len;
                if (EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &final_len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:DECRYPT_FINAL_FAILED");
                }
                EVP_CIPHER_CTX_free(ctx);

                // Return payload as hex
                std::string decrypted_hex = BytesToHex(decrypted);
                return StringVector::AddString(result, decrypted_hex);

            } catch (...) {
                return StringVector::AddString(result, "ERROR:DECRYPTION_FAILED");
            }
        });
}

// Helper function for testing OpenSSL version
inline void AesCryptoOpenSSLVersionScalarFun(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &name_vector = args.data[0];
	UnaryExecutor::Execute<string_t, string_t>(name_vector, result, args.size(), [&](string_t name) {
		return StringVector::AddString(result,
		                               "AesCrypto " + name.GetString() + ", OpenSSL version: " + OPENSSL_VERSION_TEXT);
	});
}

static void LoadInternal(DatabaseInstance &instance) {
	// Register AES encrypt function: aes_crypto_encrypt(namespace_hex, id_hex, key_hex) -> uuid_string
	auto aes_encrypt_function =
	    ScalarFunction("aes_crypto_encrypt", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, AesEncryptFunction);
	ExtensionUtil::RegisterFunction(instance, aes_encrypt_function);

	// Register AES decrypt function: aes_crypto_decrypt(uuid_string, key_hex) -> combined_hex
	auto aes_decrypt_function = ScalarFunction("aes_crypto_decrypt", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                           LogicalType::VARCHAR, AesDecryptFunction);
	ExtensionUtil::RegisterFunction(instance, aes_decrypt_function);

	// Register high-level encode function: aes_crypto_encode(namespace_hex, id_hex, key_hex) -> uuid_string
	auto encode_function =
	    ScalarFunction("aes_crypto_encode", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, EncodeFunction);
	ExtensionUtil::RegisterFunction(instance, encode_function);

	// Register high-level decode function: aes_crypto_decode(uuid_string, key_hex) -> combined_hex
	auto decode_function = ScalarFunction("aes_crypto_decode", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                      LogicalType::VARCHAR, DecodeFunction);
	ExtensionUtil::RegisterFunction(instance, decode_function);

	// Register enhanced encode function that produces valid UUIDs: aes_crypto_encode_valid(namespace_hex, id_hex,
	// key_hex) -> valid_uuid
	auto encode_valid_function =
	    ScalarFunction("aes_crypto_encode_valid", {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, EncodeValidFunction);
	ExtensionUtil::RegisterFunction(instance, encode_valid_function);

	// Register enhanced decode function that handles valid UUIDs: aes_crypto_decode_valid(valid_uuid, key_hex) ->
	// combined_hex
	auto decode_valid_function = ScalarFunction("aes_crypto_decode_valid", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                                            LogicalType::VARCHAR, DecodeValidFunction);
	ExtensionUtil::RegisterFunction(instance, decode_valid_function);

	// Register OpenSSL version check function for debugging
	auto aes_crypto_openssl_version_scalar_function = ScalarFunction(
	    "aes_crypto_openssl_version", {LogicalType::VARCHAR}, LogicalType::VARCHAR, AesCryptoOpenSSLVersionScalarFun);
	ExtensionUtil::RegisterFunction(instance, aes_crypto_openssl_version_scalar_function);

	// Register simplified valid UUID API (single payload)
	auto encode_valid_uuid_function =
	    ScalarFunction("aes_crypto_encode_valid_uuid", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, EncodeValidUuidFunction);
	ExtensionUtil::RegisterFunction(instance, encode_valid_uuid_function);

	auto decode_valid_uuid_function =
	    ScalarFunction("aes_crypto_decode_valid_uuid", {LogicalType::VARCHAR, LogicalType::VARCHAR},
	                   LogicalType::VARCHAR, DecodeValidUuidFunction);
	ExtensionUtil::RegisterFunction(instance, decode_valid_uuid_function);
}

void AesCryptoExtension::Load(DuckDB &db) {
	LoadInternal(*db.instance);
}
std::string AesCryptoExtension::Name() {
	return "aes_crypto";
}

std::string AesCryptoExtension::Version() const {
#ifdef EXT_VERSION_AES_CRYPTO
	return EXT_VERSION_AES_CRYPTO;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_EXTENSION_API void aes_crypto_init(duckdb::DatabaseInstance &db) {
	duckdb::DuckDB db_wrapper(db);
	db_wrapper.LoadExtension<duckdb::AesCryptoExtension>();
}

DUCKDB_EXTENSION_API const char *aes_crypto_version() {
	return duckdb::DuckDB::LibraryVersion();
}
}

#ifndef DUCKDB_EXTENSION_MAIN
#error DUCKDB_EXTENSION_MAIN not defined
#endif

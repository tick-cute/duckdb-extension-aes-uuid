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
				    return StringVector::AddString(result, "ERROR:ENCRYPTION_INIT_FAILED");
			    }

			    // Encrypt
			    std::vector<uint8_t> encrypted(target_size);
			    int out_len;
			    if (EVP_EncryptUpdate(ctx, encrypted.data(), &out_len, combined_bytes.data(), combined_bytes.size()) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPTION_FAILED");
			    }

			    // Finalize
			    int final_len;
			    if (EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:ENCRYPTION_FINALIZE_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert to hex and format as UUID
			    std::string encrypted_hex = BytesToHex(encrypted);
			    std::string uuid_result = FormatAsUUID(encrypted_hex);

			    return StringVector::AddString(result, uuid_result);
		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:ENCRYPTION_EXCEPTION");
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
			    // Convert inputs
			    std::string uuid_string = uuid_str.GetString();
			    std::string key_str = key_hex.GetString();

			    // Remove dashes from UUID
			    std::string hex_no_dashes;
			    for (char c : uuid_string) {
				    if (c != '-') {
					    hex_no_dashes += c;
				    }
			    }

			    // Validate key (must be 32 bytes for AES-256)
			    auto key_bytes = HexToBytes(key_str);
			    if (key_bytes.size() != 32) {
				    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
			    }

			    // Convert hex to bytes
			    auto encrypted_bytes = HexToBytes(hex_no_dashes);

			    // Set up AES decryption
			    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
			    if (!ctx) {
				    return StringVector::AddString(result, "ERROR:CTX_CREATION_FAILED");
			    }

			    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPTION_INIT_FAILED");
			    }

			    // Decrypt
			    std::vector<uint8_t> decrypted(encrypted_bytes.size());
			    int out_len;
			    if (EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, encrypted_bytes.data(), encrypted_bytes.size()) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPTION_FAILED");
			    }

			    // Finalize
			    int final_len;
			    if (EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len) != 1) {
				    EVP_CIPHER_CTX_free(ctx);
				    return StringVector::AddString(result, "ERROR:DECRYPTION_FINALIZE_FAILED");
			    }

			    EVP_CIPHER_CTX_free(ctx);

			    // Convert to hex
			    std::string decrypted_hex = BytesToHex(decrypted);

			    return StringVector::AddString(result, decrypted_hex);
		    } catch (...) {
			    return StringVector::AddString(result, "ERROR:DECRYPTION_EXCEPTION");
		    }
	    });
}

// Simplified valid UUID encode function (single payload)
inline void EncodeValidUuidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &payload_vector = args.data[0];
	auto &key_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
        payload_vector, key_vector, result, args.size(), [&](string_t payload_hex, string_t key_hex) {
            try {
                // Convert inputs
                std::string payload_str = payload_hex.GetString();
                std::string key_str = key_hex.GetString();

                // Convert payload to bytes
                auto payload_bytes = HexToBytes(payload_str);

                // Check size limits (32 bytes max)
                if (payload_bytes.size() > 32) {
                    return StringVector::AddString(result, "ERROR:OVERSIZE");
                }

                // Validate key (must be 32 bytes for AES-256)
                auto key_bytes = HexToBytes(key_str);
                if (key_bytes.size() != 32) {
                    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
                }

                // Pad data to 16 or 32 bytes
                size_t target_size = payload_bytes.size() <= 16 ? 16 : 32;
                payload_bytes.resize(target_size, 0);

                // Set up AES encryption
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    return StringVector::AddString(result, "ERROR:CTX_CREATION_FAILED");
                }

                if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:ENCRYPTION_INIT_FAILED");
                }

                // Encrypt
                std::vector<uint8_t> encrypted(target_size);
                int out_len;
                if (EVP_EncryptUpdate(ctx, encrypted.data(), &out_len, payload_bytes.data(), payload_bytes.size()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:ENCRYPTION_FAILED");
                }

                // Finalize
                int final_len;
                if (EVP_EncryptFinal_ex(ctx, encrypted.data() + out_len, &final_len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:ENCRYPTION_FINALIZE_FAILED");
                }

                EVP_CIPHER_CTX_free(ctx);

                // Convert to hex
                std::string encrypted_hex = BytesToHex(encrypted);

                // Now make it a valid UUID by forcing version and variant bits
                // Extract original version (position 12-13) and variant (position 16-17) bits
                std::string orig_version = encrypted_hex.substr(12, 2);
                std::string orig_variant = encrypted_hex.substr(16, 2);

                // Create valid UUID v4: force version=4, variant=8,9,A,B (binary 10xx)
                // Store original bits in safe positions (positions 7-8 and 17-18)
                std::string valid_hex = encrypted_hex;
                valid_hex.replace(7, 2, orig_version);   // Store original version at position 7-8
                valid_hex.replace(12, 2, "4e");          // Force version 4 (UUID v4)
                valid_hex.replace(16, 2, "82");          // Force variant to 82 (binary 1000, valid variant)
                valid_hex.replace(17, 2, orig_variant);  // Store original variant at position 17-18

                // Format as UUID
                std::string valid_uuid = FormatAsUUID(valid_hex);

                return StringVector::AddString(result, valid_uuid);
            } catch (...) {
                return StringVector::AddString(result, "ERROR:ENCRYPTION_EXCEPTION");
            }
        });
}

// Simplified valid UUID decode function (single payload)
inline void DecodeValidUuidFunction(DataChunk &args, ExpressionState &state, Vector &result) {
	auto &uuid_vector = args.data[0];
	auto &key_vector = args.data[1];

	BinaryExecutor::Execute<string_t, string_t, string_t>(
        uuid_vector, key_vector, result, args.size(), [&](string_t uuid_str, string_t key_hex) {
            try {
                // Convert inputs
                std::string uuid_string = uuid_str.GetString();
                std::string key_str = key_hex.GetString();

                // Remove dashes from UUID
                std::string hex_no_dashes;
                for (char c : uuid_string) {
                    if (c != '-') {
                        hex_no_dashes += c;
                    }
                }

                // Validate key (must be 32 bytes for AES-256)
                auto key_bytes = HexToBytes(key_str);
                if (key_bytes.size() != 32) {
                    return StringVector::AddString(result, "ERROR:INVALID_KEY_SIZE");
                }

                // Restore original version and variant bits from hidden positions
                std::string original_hex = hex_no_dashes;
                // Get the hex digit pairs at the stored positions
                std::string orig_version = hex_no_dashes.substr(7, 2);  // Retrieve original version from position 7-8
                std::string orig_variant = hex_no_dashes.substr(17, 2); // Retrieve original variant from position 17-18

                original_hex.replace(12, 2, orig_version); // Restore original version at position 12-13
                original_hex.replace(16, 2, orig_variant); // Restore original variant at position 16-17

                auto encrypted_bytes = HexToBytes(original_hex);

                // Set up AES decryption
                EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
                if (!ctx) {
                    return StringVector::AddString(result, "ERROR:CTX_CREATION_FAILED");
                }

                if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key_bytes.data(), nullptr) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:DECRYPTION_INIT_FAILED");
                }

                // Decrypt
                std::vector<uint8_t> decrypted(encrypted_bytes.size());
                int out_len;
                if (EVP_DecryptUpdate(ctx, decrypted.data(), &out_len, encrypted_bytes.data(), encrypted_bytes.size()) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:DECRYPTION_FAILED");
                }

                // Finalize
                int final_len;
                if (EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len) != 1) {
                    EVP_CIPHER_CTX_free(ctx);
                    return StringVector::AddString(result, "ERROR:DECRYPTION_FINALIZE_FAILED");
                }

                EVP_CIPHER_CTX_free(ctx);

                // Convert to hex
                std::string decrypted_hex = BytesToHex(decrypted);

                return StringVector::AddString(result, decrypted_hex);
            } catch (...) {
                return StringVector::AddString(result, "ERROR:DECRYPTION_EXCEPTION");
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

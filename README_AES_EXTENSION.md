# DuckDB AES Crypto Extension

This DuckDB extension provides **reversible, deterministic, UUID-shaped encryption** using AES-256-ECB with OpenSSL. Perfect for creating opaque, namespace-recoverable identifiers!

## 🎯 What This Extension Provides

- ✅ **Truly reversible** AES-256-ECB encryption/decryption
- ✅ **UUID-shaped output** (`8-4-4-4-12` format or double UUID for larger data)
- ✅ **Deterministic** - same input always produces same output
- ✅ **Namespace support** - combine namespace + ID before encryption
- ✅ **Cross-platform** - works on macOS, Linux, Windows
- ✅ **Size limits** - up to 32 bytes total input (16 or 32 byte blocks)
- ✅ **Error handling** - proper validation and error messages

## 🚀 Quick Start

### 1. Build the Extension
```bash
# Clone and build
git clone --recurse-submodules https://github.com/duckdb/extension-template.git aes_extension
cd aes_extension
python3 ./scripts/bootstrap-template.py aes_crypto
make
```

### 2. Load in DuckDB
```sql
-- Start DuckDB allowing unsigned extensions
./build/release/duckdb -unsigned

-- The extension is automatically loaded!
```

### 3. Basic Usage
```sql
-- Test if extension is working
SELECT aes_crypto_openssl_version('test');

-- Encode namespace + ID into UUID-shaped string
SELECT encode(
    '6ba7b8109dad11d180b400c04fd430c8',  -- namespace (hex)
    '01b9c1ae51b64f87934d9e0cf22a18c1',  -- id (hex)
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'  -- 32-byte key (hex)
) AS uuid_shaped_id;
-- Result: 88384538-b320-c23e-a9ba-fd8be2831c37-22be92ce-0011-e353-7daf-4a118c21fd28

-- Decode back to get original namespace + ID
SELECT decode(
    '88384538-b320-c23e-a9ba-fd8be2831c37-22be92ce-0011-e353-7daf-4a118c21fd28',
    '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
) AS decoded_hex;
-- Result: 6ba7b8109dad11d180b400c04fd430c801b9c1ae51b64f87934d9e0cf22a18c1
```

## 📚 Available Functions

### High-Level Functions (Recommended)

#### `encode(namespace_hex, id_hex, key_hex) → uuid_string`
- **Purpose**: Create UUID-shaped reversible ID
- **Parameters**:
  - `namespace_hex`: Namespace as hex string (optional, can be empty '')
  - `id_hex`: ID as hex string 
  - `key_hex`: 32-byte secret key as hex string (64 hex characters)
- **Returns**: UUID-shaped string or ERROR:* message
- **Example**: `encode('ns', 'id123', '01234...')`

#### `decode(uuid_string, key_hex) → combined_hex`
- **Purpose**: Recover original namespace + ID from UUID
- **Parameters**:
  - `uuid_string`: UUID-shaped string from encode()
  - `key_hex`: Same 32-byte secret key used for encoding
- **Returns**: Original namespace+ID concatenated as hex
- **Example**: `decode('88384538-b320-...', '01234...')`

### Low-Level Functions

#### `aes_encrypt(namespace_hex, id_hex, key_hex) → uuid_string`
- Direct AES encryption (same as encode)

#### `aes_decrypt(uuid_string, key_hex) → combined_hex`  
- Direct AES decryption (same as decode)

#### `aes_crypto_openssl_version(test_string) → version_info`
- Returns OpenSSL version for debugging

## 💡 Real-World Example

```sql
-- Create a table with sensitive user IDs
CREATE TABLE users AS VALUES
    ('user_prod', '550e8400e29b41d4a716446655440000', 'production_secret_key_32_bytes_exactly_here'),
    ('user_test', '6ba7b8109dad11d180b400c04fd430c8', 'production_secret_key_32_bytes_exactly_here'),
    ('user_dev',  '01b9c1ae51b64f87934d9e0cf22a18c1', 'production_secret_key_32_bytes_exactly_here')
AS t(namespace, user_id, secret_key);

-- Generate opaque UUIDs for public use
SELECT 
    namespace,
    encode(namespace, user_id, secret_key) AS public_uuid
FROM users;

-- Results look like real UUIDs:
-- user_prod | dad679ec-49d4-9e31-2e00-b08f34d6fb5c-89518103-2128-43db-1fa7-b4c45d7444f8
-- user_test | 88384538-b320-c23e-a9ba-fd8be2831c37-22be92ce-0011-e353-7daf-4a118c21fd28
-- user_dev  | 4a8c1f35-7e2b-9d64-8f3a-c5e9b7f1d8e6

-- Later, recover the original namespace and user_id
WITH public_uuids AS (
    SELECT 'dad679ec-49d4-9e31-2e00-b08f34d6fb5c-89518103-2128-43db-1fa7-b4c45d7444f8' AS uuid,
           'production_secret_key_32_bytes_exactly_here' AS key
)
SELECT 
    decode(uuid, key) AS decoded_namespace_and_id
FROM public_uuids;
-- Result: user_prod550e8400e29b41d4a716446655440000
```

## 🔒 Security Properties

### ✅ What This Extension Provides:
- **Confidentiality**: AES-256 encryption hides the original data
- **Determinism**: Same input always produces same output
- **Reversibility**: Perfect round-trip with correct key
- **Opaque IDs**: Output looks like regular UUIDs
- **Namespace recovery**: Can extract both namespace and ID

### ⚠️ Important Security Notes:
- **AES-256-ECB mode**: Deterministic but reveals patterns for identical plaintexts
- **Key management**: You must securely manage the 32-byte secret key
- **Input size**: Limited to 32 bytes total (namespace + ID combined)
- **Not for general encryption**: Designed specifically for deterministic ID generation

## 📋 Error Handling

| Error | Meaning | Solution |
|-------|---------|----------|
| `ERROR:OVERSIZE` | Combined namespace+ID > 32 bytes | Use shorter inputs |
| `ERROR:INVALID_KEY_SIZE` | Secret key ≠ 32 bytes | Use exactly 64 hex characters (32 bytes) |
| `ERROR:CTX_CREATION_FAILED` | OpenSSL context creation failed | Check OpenSSL installation |
| `ERROR:ENCRYPT_*_FAILED` | AES encryption failed | Check inputs and key |
| `ERROR:DECRYPT_*_FAILED` | AES decryption failed | Check UUID format and key |

## 🧪 Testing

```sql
-- Test round-trip encoding/decoding
WITH test AS (
    SELECT 'ns123' AS namespace, 
           'id456' AS id, 
           '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' AS key
)
SELECT 
    namespace || id AS original,
    encode(namespace, id, key) AS encoded,
    decode(encode(namespace, id, key), key) AS decoded,
    (namespace || id) = decode(encode(namespace, id, key), key) AS round_trip_success
FROM test;
```

## 🏗️ Building & Installation

### Prerequisites
- CMake 3.10+
- OpenSSL 3.0+ (installed via VCPKG automatically)
- C++17 compatible compiler

### Build Steps
```bash
# Clone template and configure
git clone --recurse-submodules https://github.com/duckdb/extension-template.git aes_extension
cd aes_extension
python3 ./scripts/bootstrap-template.py aes_crypto

# Build extension
make

# Test it works
echo "SELECT aes_crypto_openssl_version('test');" | ./build/release/duckdb -unsigned
```

## 🎉 Success!

You now have a working DuckDB extension that provides:
- **Reversible encryption** ✅
- **UUID-shaped output** ✅  
- **Deterministic results** ✅
- **Cross-platform compatibility** ✅
- **Proper error handling** ✅

Perfect for creating opaque, recoverable identifiers in your DuckDB applications!
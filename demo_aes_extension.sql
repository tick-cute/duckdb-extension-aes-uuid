-- DuckDB AES Crypto Extension Demo
-- This demonstrates the reversible, UUID-shaped ID system

-- Check OpenSSL version
SELECT 'OpenSSL Version Test:' AS test_name, aes_crypto_openssl_version('DuckDB') AS result;

-- Test data setup
CREATE TABLE test_data AS VALUES
    ('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    ('', '550e8400e29b41d4a716446655440000', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'), 
    ('a1b2c3d4e5f6', '123456789abcdef0', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
AS t(namespace, id, secret_key);

-- Test 1: Basic Encoding 
SELECT 'Test 1 - Basic Encoding:' AS test_name;
SELECT 
    namespace, 
    id, 
    aes_crypto_encode(namespace, id, secret_key) AS uuid_shaped_id,
    length(aes_crypto_encode(namespace, id, secret_key)) AS uuid_length
FROM test_data;

-- Test 2: Round-trip Encoding/Decoding
SELECT 'Test 2 - Round-trip Test:' AS test_name;
WITH encoded AS (
    SELECT 
        namespace,
        id, 
        secret_key,
        aes_crypto_encode(namespace, id, secret_key) AS uuid_shaped_id
    FROM test_data
)
SELECT 
    namespace || id AS original_combined,
    aes_crypto_decode(uuid_shaped_id, secret_key) AS decoded_combined,
    (namespace || id) = aes_crypto_decode(uuid_shaped_id, secret_key) AS round_trip_success
FROM encoded
WHERE uuid_shaped_id NOT LIKE 'ERROR:%';

-- Test 3: Error Handling - Oversize Data
SELECT 'Test 3 - Oversize Detection:' AS test_name;
SELECT aes_crypto_encode('', repeat('a', 68), '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS oversize_result;

-- Test 4: Error Handling - Invalid Key Size  
SELECT 'Test 4 - Invalid Key Size:' AS test_name;
SELECT aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', 'tooshort') AS invalid_key_result;

-- Test 5: Different Key Test (should produce different results)
SELECT 'Test 5 - Different Keys Produce Different Results:' AS test_name;
SELECT 
    aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS result_key1,
    aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210') AS result_key2,
    aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') 
    != aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210') AS keys_produce_different_results;

-- Test 6: Deterministic Test (same input should always produce same output)
SELECT 'Test 6 - Deterministic Results:' AS test_name;
SELECT 
    aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS run1,
    aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS run2,
    aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') 
    = aes_crypto_encode('6ba7b8109dad11d180b400c04fd430c8', '01b9c1ae51b64f87934d9e0cf22a18c1', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS is_deterministic;

-- Test 7: Valid UUID single-payload helper
SELECT 'Test 7 - encode_valid_uuid / decode_valid_uuid:' AS test_name;
WITH encoded AS (
    SELECT aes_crypto_encode_valid_uuid(hex('namespace:hello'), '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS uuid_val
),
decoded AS (
    SELECT aes_crypto_decode_valid_uuid(uuid_val, '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef') AS decoded_hex
    FROM encoded
)
SELECT unhex(substr(decoded_hex, 1, 20)) AS payload_prefix FROM decoded;

SELECT 'SUCCESS: All tests completed! 🎉' AS final_message;
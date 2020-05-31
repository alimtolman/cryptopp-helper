#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#pragma warning(push, 0) 
#include "aes.h"
#include "dh.h"
#include "filters.h"
#include "md2.h"
#include "md4.h"
#include "md5.h"
#include "modes.h"
#include "osrng.h"
#include "poly1305.h"
#include "pwdbased.h"
#include "rsa.h"
#include "salsa.h"
#include "sha.h"
#pragma warning(pop)

#include "main.h"

using namespace CryptoPP;

#pragma region helpers

void delete_byte_array(const byte* bytes) {
    delete[] bytes;
}

#pragma endregion

#pragma region aes

void aes_cbc_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    CBC_Mode<AES>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_cbc_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    CBC_Mode<AES>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_cfb_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    std::string output_str = "";

    CFB_Mode<AES>::Decryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), BlockPaddingSchemeDef::ZEROS_PADDING);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_cfb_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, const byte* iv_bytes, byte** output_bytes) {
    std::string output_str = "";

    CFB_Mode<AES>::Encryption engine(key_bytes, key_size, iv_bytes);
    StreamTransformationFilter stream(engine, new StringSink(output_str), BlockPaddingSchemeDef::ZEROS_PADDING);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_ecb_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    ECB_Mode<AES>::Decryption engine(key_bytes, key_size);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

void aes_ecb_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const unsigned int key_size, byte** output_bytes, unsigned int* output_size, const bool zeros_padding = false) {
    std::string output_str = "";
    const BlockPaddingSchemeDef::BlockPaddingScheme padding = zeros_padding ? BlockPaddingSchemeDef::ZEROS_PADDING : BlockPaddingSchemeDef::PKCS_PADDING;

    ECB_Mode<AES>::Encryption engine(key_bytes, key_size);
    StreamTransformationFilter stream(engine, new StringSink(output_str), padding);
    stream.Put(input_bytes, input_size);
    stream.MessageEnd();

    *output_size = static_cast<unsigned int>(output_str.size());
    *output_bytes = new byte[output_str.size()];

    for (unsigned int i = 0; i < output_str.size(); ++i)
        (*output_bytes)[i] = static_cast<byte>(output_str.at(i));
}

#pragma endregion

#pragma region big integer

void big_integer_mod_pow(const char* value_hex, const char* exponent_hex, const char* modulus_hex, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    Integer value(value_hex);
    Integer exponent(exponent_hex);
    Integer modulus(modulus_hex);
    Integer result(1);

    value %= modulus;

    while (exponent > 0) {
        if ((exponent & 1) == 1)
            result = (result * value) % modulus;

        value = (value * value) % modulus;
        exponent >>= 1;
    }

    result.Encode(buffer, result.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

#pragma endregion

#pragma region diffie-hellman

void dh_key_pair(const char* p_hex, const char* g_hex, byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    DH dh;
    AutoSeededRandomPool rng;
    Integer p(p_hex);
    Integer g(g_hex);

    dh.AccessGroupParameters().Initialize(p, g);

    *private_key_size = dh.PrivateKeyLength();
    *public_key_size = dh.PublicKeyLength();
    *private_key_bytes = new byte[*private_key_size];
    *public_key_bytes = new byte[*public_key_size];
    
    dh.GenerateKeyPair(rng, *private_key_bytes, *public_key_bytes);
}

void dh_shared_key(const char* p_hex, const char* g_hex, const byte* private_key_bytes, const byte* other_public_key_bytes, byte** shared_key_bytes, unsigned int* shared_key_size) {
    DH dh;
    Integer p(p_hex);
    Integer g(g_hex);

    dh.AccessGroupParameters().Initialize(p, g);

    *shared_key_size = dh.AgreedValueLength();
    *shared_key_bytes = new byte[*shared_key_size];

    dh.Agree(*shared_key_bytes, private_key_bytes, other_public_key_bytes);
}

#pragma endregion

#pragma region hash

void md2(const byte* input_bytes, const unsigned int input_size, byte** output_bytes) {
    Weak::MD2().CalculateDigest(*output_bytes, input_bytes, input_size);
}

void md4(const byte* input_bytes, const unsigned int input_size, byte** output_bytes) {
    Weak::MD4().CalculateDigest(*output_bytes, input_bytes, input_size);
}

void md5(const byte* input_bytes, const unsigned int input_size, byte** output_bytes) {
    Weak::MD5().CalculateDigest(*output_bytes, input_bytes, input_size);
}

void poly1305_tls(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, byte** output_bytes) {
    Poly1305TLS mac;

    mac.SetKey(key_bytes, Poly1305TLS::KEYLENGTH);
    mac.Update(input_bytes, input_size);
    mac.Final(*output_bytes);
}

#pragma endregion

#pragma region pbkdf2

void pbkdf2_hmac_sha1(const byte* password_bytes, const unsigned int password_size, const byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, byte** output_bytes, const unsigned int output_size) {
    PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;

    pbkdf2.DeriveKey(*output_bytes, output_size, 0, password_bytes, password_size, salt_bytes, salt_size, iterations_count);
}

void pbkdf2_hmac_sha256(const byte* password_bytes, const unsigned int password_size, const byte* salt_bytes, const unsigned int salt_size, const unsigned int iterations_count, byte** output_bytes, const unsigned int output_size) {
    PKCS5_PBKDF2_HMAC<SHA256> pbkdf2;

    pbkdf2.DeriveKey(*output_bytes, output_size, 0, password_bytes, password_size, salt_bytes, salt_size, iterations_count);
}

#pragma endregion

#pragma region rsa

void rsa_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<PKCS1v15>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<PKCS1v15>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_export_public_key(const byte* private_key_bytes, const unsigned int private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;
    RSA::PublicKey public_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);
    public_key.Initialize(private_key.GetModulus(), private_key.GetPublicExponent());
    
    buffer.Clear();
    public_key.DEREncode(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void rsa_key_pair(const unsigned int key_size, byte** private_key_bytes, unsigned int* private_key_size, byte** public_key_bytes, unsigned int* public_key_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSA::PrivateKey private_key;
    RSA::PublicKey public_key;

    private_key.GenerateRandomWithKeySize(rng, key_size);
    public_key.Initialize(private_key.GetModulus(), private_key.GetPublicExponent());

    private_key.DEREncode(buffer);

    *private_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *private_key_bytes = new byte[*private_key_size];

    buffer.Get(*private_key_bytes, *private_key_size);

    buffer.Clear();
    public_key.DEREncode(buffer);

    *public_key_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *public_key_bytes = new byte[*public_key_size];

    buffer.Get(*public_key_bytes, *public_key_size);
}

void rsa_no_padding_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    AutoSeededRandomPool rng;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    Integer decrypted = private_key.CalculateInverse(rng, Integer(input_bytes, input_size));

    buffer.Clear();
    decrypted.Encode(buffer, decrypted.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_no_padding_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    Integer encrypted = public_key.ApplyFunction(Integer(input_bytes, input_size));

    buffer.Clear();
    encrypted.Encode(buffer, encrypted.ByteCount());

    *output_size = static_cast<unsigned int>(buffer.TotalBytesRetrievable());
    *output_bytes = new byte[*output_size];

    buffer.Get(*output_bytes, *output_size);
}

void rsa_oaep_md2_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD2>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_md2_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD2>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_md4_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD4>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_md4_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD4>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_md5_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD5>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_md5_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<Weak::MD5>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_sha1_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA1>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_sha1_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA1>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_sha224_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA224>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_sha224_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA224>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_sha256_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_sha256_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA256>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_sha384_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA384>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_sha384_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA384>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_oaep_sha512_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA512>>::Decryptor engine(private_key);

    *output_bytes = new byte[engine.MaxPlaintextLength(input_size)];
    *output_size = static_cast<unsigned int>(engine.Decrypt(rng, input_bytes, input_size, *output_bytes).messageLength);
}

void rsa_oaep_sha512_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* public_key_bytes, const unsigned int public_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSAES<OAEP<SHA512>>::Encryptor engine(public_key);

    *output_size = static_cast<unsigned int>(engine.CiphertextLength(input_size));
    *output_bytes = new byte[*output_size];

    engine.Encrypt(rng, input_bytes, input_size, *output_bytes);
}

void rsa_pss_md2_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, Weak::MD2>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_md2_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, Weak::MD2>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_md5_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, Weak::MD5>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_md5_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, Weak::MD5>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha1_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA1>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha1_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, SHA1>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha224_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA224>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha224_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, SHA224>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha256_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA256>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha256_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, SHA256>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha384_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA384>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha384_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, SHA384>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

void rsa_pss_sha512_sign(const byte* input_bytes, const unsigned int input_size, const byte* private_key_bytes, const unsigned int private_key_size, byte** output_bytes, unsigned int* output_size) {
    ByteQueue buffer;
    RSA::PrivateKey private_key;

    buffer.Put(private_key_bytes, private_key_size);
    buffer.MessageEnd();
    private_key.BERDecode(buffer);

    AutoSeededRandomPool rng;
    RSASS<PKCS1v15, SHA512>::Signer signer(private_key);

    *output_bytes = new byte[signer.MaxSignatureLength()];
    *output_size = static_cast<unsigned int>(signer.SignMessage(rng, input_bytes, input_size, *output_bytes));
}

void rsa_pss_sha512_verify(const byte* input_bytes, const unsigned int input_size, const byte* signature_bytes, const unsigned int signature_size, const byte* public_key_bytes, const unsigned int public_key_size, bool* result) {
    ByteQueue buffer;
    RSA::PublicKey public_key;

    buffer.Put(public_key_bytes, public_key_size);
    buffer.MessageEnd();
    public_key.BERDecode(buffer);

    RSASS<PKCS1v15, SHA512>::Verifier verifier(public_key);

    *result = verifier.VerifyMessage(input_bytes, input_size, signature_bytes, signature_size);
}

#pragma endregion

#pragma region xsalsa20

void xsalsa20_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes) {
    XSalsa20::Decryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

void xsalsa20_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes) {
    XSalsa20::Encryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(*output_bytes, input_bytes, input_size);
}

void xsalsa20_poly1305_tls_decrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes, const bool verify = true) {
    const unsigned int encrypted_size = input_size - Poly1305TLS::DIGESTSIZE;
    byte* encrypted_bytes = new byte[encrypted_size];
    byte* main_hash_bytes = new byte[Poly1305TLS::DIGESTSIZE];
    byte* other_hash_bytes = new byte[Poly1305TLS::DIGESTSIZE];
    byte sub_key_bytes[Poly1305TLS::KEYLENGTH] = {};

    memcpy(encrypted_bytes, input_bytes + Poly1305TLS::DIGESTSIZE, encrypted_size);
    memcpy(other_hash_bytes, input_bytes, Poly1305TLS::DIGESTSIZE);

    XSalsa20::Decryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(sub_key_bytes, sub_key_bytes, Poly1305TLS::KEYLENGTH);

    if (verify)
        poly1305_tls(encrypted_bytes, encrypted_size, sub_key_bytes, &main_hash_bytes);

    if (!verify || (memcmp(main_hash_bytes, other_hash_bytes, Poly1305TLS::DIGESTSIZE) == 0))
        engine.ProcessData(*output_bytes, encrypted_bytes, encrypted_size);

    delete[] encrypted_bytes;
    delete[] main_hash_bytes;
    delete[] other_hash_bytes;
}

void xsalsa20_poly1305_tls_encrypt(const byte* input_bytes, const unsigned int input_size, const byte* key_bytes, const byte* iv_bytes, byte** output_bytes) {
    byte* encrypted_bytes = new byte[input_size];
    byte* hash_bytes = new byte[Poly1305TLS::DIGESTSIZE];
    byte sub_key_bytes[Poly1305TLS::KEYLENGTH] = {};
    
    XSalsa20::Encryption engine;

    engine.SetKeyWithIV(key_bytes, XSalsa20::KEYLENGTH, iv_bytes, XSalsa20::IV_LENGTH);
    engine.ProcessData(sub_key_bytes, sub_key_bytes, Poly1305TLS::KEYLENGTH);
    engine.ProcessData(encrypted_bytes, input_bytes, input_size);

    poly1305_tls(encrypted_bytes, input_size, sub_key_bytes, &hash_bytes);

    memcpy(*output_bytes, hash_bytes, Poly1305TLS::DIGESTSIZE);
    memcpy(*output_bytes + Poly1305TLS::DIGESTSIZE, encrypted_bytes, input_size);

    delete[] encrypted_bytes;
    delete[] hash_bytes;
}

#pragma endregion

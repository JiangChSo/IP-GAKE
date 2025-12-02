#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <chrono>
#include <sstream> // Required for std::ostringstream

// Crypto++ Headers
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"     // For curve definitions
#include "cryptopp/sha.h"      // For SHA256
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/hkdf.h"
#include "cryptopp/filters.h"
#include "cryptopp/secblock.h"
#include "cryptopp/ecp.h"

// Check if NUM_PARTICIPANTS is defined by the compiler flag, otherwise set a default
#ifndef NUM_PARTICIPANTS
#define NUM_PARTICIPANTS 32
#endif

using namespace CryptoPP;

// --- Type Aliases for Clarity ---
using ECPPoint = ECP::Point;
using Integer = CryptoPP::Integer;

// --- Helper Functions ---

// Generic SHA256 hashing function for 112-bit+ security
std::string sha256_hash(const std::string& input) {
    SHA256 hash;
    std::string digest;
    StringSource(input, true, new HashFilter(hash, new StringSink(digest)));
    return digest;
}

// Serialize an ECPPoint to a string for hashing/encryption
std::string ECPPointToString(const DL_GroupParameters_EC<ECP>& params, const ECPPoint& point) {
    std::string s;
    StringSink ss(s);
    params.GetCurve().EncodePoint(ss, point, false); // false for uncompressed
    return s;
}

// Simulates the tweakable cipher using HKDF
void encrypt_tweakable(const std::string& password, const std::string& tweak, const std::string& plaintext, std::string& ciphertext) {
    SecByteBlock derived(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE);
    HKDF<SHA256> hkdf; // Using SHA256 for KDF
    hkdf.DeriveKey(derived, derived.size(), (const byte*)password.data(), password.size(), (const byte*)tweak.data(), tweak.size(), nullptr, 0);

    SecByteBlock key(derived.data(), AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(derived.data() + AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE);
    
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv);
    StringSource(plaintext, true, new StreamTransformationFilter(e, new StringSink(ciphertext)));
}

// Decrypts using the same tweakable mechanism
void decrypt_tweakable(const std::string& password, const std::string& tweak, const std::string& ciphertext, std::string& plaintext) {
    SecByteBlock derived(AES::DEFAULT_KEYLENGTH + AES::BLOCKSIZE);
    HKDF<SHA256> hkdf; // Using SHA256 for KDF
    hkdf.DeriveKey(derived, derived.size(), (const byte*)password.data(), password.size(), (const byte*)tweak.data(), tweak.size(), nullptr, 0);
    
    SecByteBlock key(derived.data(), AES::DEFAULT_KEYLENGTH);
    SecByteBlock iv(derived.data() + AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE);

    try {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);
        StringSource(ciphertext, true, new StreamTransformationFilter(d, new StringSink(plaintext)));
    } catch(const Exception&) {
        plaintext = "";
    }
}


// --- Player State ---
struct Player {
    int id;
    Integer x_i;
    ECPPoint z_i;
    std::string z_i_star;
    std::string c_i;

    ECDSA<ECP, SHA256>::PrivateKey sig_sk; // Signature uses SHA256
    ECDSA<ECP, SHA256>::PublicKey sig_vk;

    ECPPoint z_i_minus_1;
    ECPPoint z_i_plus_1;
    ECPPoint Z_i;
    ECPPoint Z_i_plus_1;

    std::string h_i;
    std::string h_i_plus_1;
    std::string X_i;
    std::string c_i_prime;
    std::string authenticator;
    std::string signature;
    std::string session_key;
};


int main() {
    AutoSeededRandomPool prng;

    // =================================================================
    // 1. SETUP PHASE
    // =================================================================
    auto setup_start = std::chrono::high_resolution_clock::now();

    const int n = NUM_PARTICIPANTS;
    std::vector<Player> players(n);

    // Using secp224r1 for 112-bit security level
    DL_GroupParameters_EC<ECP> params(ASN1::secp224r1());
    const ECPPoint& g = params.GetSubgroupGenerator();
    const Integer& q = params.GetSubgroupOrder();

    std::string password = "correct-horse-battery-staple";
    std::string ssid = "session_identifier_12345";

    auto setup_end = std::chrono::high_resolution_clock::now();

    // =================================================================
    // 2. KEY EXCHANGE PHASE
    // =================================================================
    auto exchange_start = std::chrono::high_resolution_clock::now();

    // --- ROUND 1a: Generate ephemeral values and first commitment ---
    for (int i = 0; i < n; ++i) {
        players[i].id = i;
        players[i].x_i.Randomize(prng, Integer::One(), q - 1);
        players[i].z_i = params.ExponentiateBase(players[i].x_i);

        std::string tweak = ssid + std::to_string(i);
        encrypt_tweakable(password, tweak, ECPPointToString(params, players[i].z_i), players[i].z_i_star);

        // Initialize signature keys with the 112-bit curve
        players[i].sig_sk.Initialize(prng, ASN1::secp224r1());
        players[i].sig_sk.MakePublicKey(players[i].sig_vk);

        std::string vk_str;
        StringSink ss(vk_str);
        players[i].sig_vk.Save(ss);
        
        players[i].c_i = sha256_hash(ssid + players[i].z_i_star + vk_str + std::to_string(i));
    }

    std::string ssid_prime = ssid;
    for (int i = 0; i < n; ++i) {
        ssid_prime += players[i].c_i;
    }


    // --- ROUND 2a: Check commitments, compute DH values, and second commitment ---
    for (int i = 0; i < n; ++i) {
        int i_minus_1 = (i == 0) ? n - 1 : i - 1;
        int i_plus_1 = (i == n - 1) ? 0 : i + 1;

        std::string tweak_minus_1 = ssid + std::to_string(i_minus_1);
        std::string tweak_plus_1 = ssid + std::to_string(i_plus_1);
        std::string decrypted_z_minus_1_str, decrypted_z_plus_1_str;
        
        decrypt_tweakable(password, tweak_minus_1, players[i_minus_1].z_i_star, decrypted_z_minus_1_str);
        decrypt_tweakable(password, tweak_plus_1, players[i_plus_1].z_i_star, decrypted_z_plus_1_str);
        
        StringSource ss_minus_1(decrypted_z_minus_1_str, true);
        params.GetCurve().DecodePoint(players[i].z_i_minus_1, ss_minus_1, ss_minus_1.MaxRetrievable());
        
        StringSource ss_plus_1(decrypted_z_plus_1_str, true);
        params.GetCurve().DecodePoint(players[i].z_i_plus_1, ss_plus_1, ss_plus_1.MaxRetrievable());

        players[i].Z_i = params.ExponentiateElement(players[i].z_i_minus_1, players[i].x_i);
        players[i].Z_i_plus_1 = params.ExponentiateElement(players[i].z_i_plus_1, players[i].x_i);

        players[i].h_i = sha256_hash(ECPPointToString(params, players[i].Z_i));
        players[i].h_i_plus_1 = sha256_hash(ECPPointToString(params, players[i].Z_i_plus_1));
        
        players[i].X_i.resize(players[i].h_i.size());
        for(size_t j=0; j < players[i].h_i.size(); ++j) {
            players[i].X_i[j] = players[i].h_i[j] ^ players[i].h_i_plus_1[j];
        }

        players[i].c_i_prime = sha256_hash(ssid_prime + players[i].X_i + std::to_string(i));
    }

    
    // --- ROUND 3: Compute authenticators and sign them ---
    std::vector<std::string> all_h(n);
    for (int i = 0; i < n; ++i) {
        all_h[i] = players[i].h_i;
        std::string current_h = players[i].h_i_plus_1;
        for (int k = 1; k < n; ++k) {
            int current_idx = (i + k) % n;
            all_h[(current_idx + 1) % n] = current_h;
            
            std::string next_h(players[current_idx].X_i.size(), '\0');
            for(size_t b=0; b < players[current_idx].X_i.size(); ++b) {
                next_h[b] = players[current_idx].X_i[b] ^ current_h[b];
            }
            current_h = next_h;
        }

        std::string auth_payload = ssid_prime;
        for (int j = 0; j < n; ++j) {
            auth_payload += players[j].z_i_star + players[j].X_i + all_h[j];
        }
        auth_payload += std::to_string(i);
        players[i].authenticator = sha256_hash(auth_payload);

        ECDSA<ECP, SHA256>::Signer signer(players[i].sig_sk);
        size_t sig_len = signer.MaxSignatureLength();
        players[i].signature.resize(sig_len);
        sig_len = signer.SignMessage(prng, (const byte*)players[i].authenticator.data(), players[i].authenticator.size(), (byte*)players[i].signature.data());
        players[i].signature.resize(sig_len);
    }

    // --- ROUND 4: Verify signatures and compute session key ---
    for (int i = 0; i < n; ++i) {
        bool all_sigs_valid = true;
        for (int j = 0; j < n; ++j) {
            ECDSA<ECP, SHA256>::Verifier verifier(players[j].sig_vk);
            if (!verifier.VerifyMessage((const byte*)players[j].authenticator.data(), players[j].authenticator.size(), (const byte*)players[j].signature.data(), players[j].signature.size())) {
                all_sigs_valid = false;
                break;
            }
        }

        if (all_sigs_valid) {
            std::string key_payload = ssid_prime;
            for(const auto& h : all_h) {
                key_payload += h;
            }
            players[i].session_key = sha256_hash(key_payload);
        } else {
            players[i].session_key = "ERROR";
        }
    }

    auto exchange_end = std::chrono::high_resolution_clock::now();
    
    // =================================================================
    // 3. OUTPUT RESULTS & VERIFICATION
    // =================================================================
    std::chrono::duration<double, std::milli> setup_duration = setup_end - setup_start;
    std::chrono::duration<double, std::milli> exchange_duration = exchange_end - exchange_start;

    std::cout << "Total Setup computation time: " << setup_duration.count() << " ms" << std::endl;
    std::cout << "Total Key Exchange computation time: " << exchange_duration.count() << " ms" << std::endl;
    std::cout << "--------------------------------------------------" << std::endl;

    // Final check and verification output
    bool success = true;
    if (players[0].session_key == "ERROR") {
        success = false;
    } else {
        for (int i = 1; i < n; ++i) {
            if (players[i].session_key != players[0].session_key) {
                success = false;
                break;
            }
        }
    }

    if (success) {
        std::cout << "✅ SUCCESS: All participants shared the same secret key." << std::endl;
        std::string encoded_key;
        StringSource(players[0].session_key, true,
            new HexEncoder(new StringSink(encoded_key))
        );
        std::cout << "Shared Key (Hex): " << encoded_key << std::endl;
    } else {
        std::cout << "❌ FAILURE: Participants did not agree on a key." << std::endl;
        for (int i = 0; i < n; ++i) {
            std::cout << "  - Player " << i << " key: " << players[i].session_key << std::endl;
        }
    }

    return 0;
}
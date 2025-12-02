#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <chrono>
#include <sstream>

// Crypto++ Headers
#include "cryptopp/osrng.h"
#include "cryptopp/eccrypto.h"
#include "cryptopp/oids.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/hkdf.h"
#include "cryptopp/filters.h"
#include "cryptopp/secblock.h"
#include "cryptopp/ecp.h"

// Check if NUM_PARTICIPANTS is defined by the compiler flag
#ifndef NUM_PARTICIPANTS
#define NUM_PARTICIPANTS 4
#endif

using namespace CryptoPP;

// --- Type Aliases for Clarity ---
using ECPPoint = ECP::Point;
using Integer = CryptoPP::Integer;

// --- Helper Functions ---

std::string sha256_hash(const std::string& input) {
    SHA256 hash;
    std::string digest;
    StringSource(input, true, new HashFilter(hash, new StringSink(digest)));
    return digest;
}

std::string ECPPointToString(const DL_GroupParameters_EC<ECP>& params, const ECPPoint& point) {
    std::string s;
    StringSink ss(s);
    params.GetCurve().EncodePoint(ss, point, false); // false for uncompressed
    return s;
}

// Derives a unique symmetric key for a player based on session ID, index, and password
SecByteBlock derive_symmetric_key(const std::string& session_id, int player_index, const std::string& password) {
    std::string salt = session_id + std::to_string(player_index);
    SecByteBlock derived_key(AES::DEFAULT_KEYLENGTH);
    HKDF<SHA256> hkdf;
    hkdf.DeriveKey(derived_key, derived_key.size(), (const byte*)password.data(), password.size(), (const byte*)salt.data(), salt.size(), nullptr, 0);
    return derived_key;
}

void aes_encrypt(const SecByteBlock& key, const std::string& plaintext, std::string& ciphertext) {
    byte iv[AES::BLOCKSIZE] = {0};
    CBC_Mode<AES>::Encryption e;
    e.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
    StringSource(plaintext, true, new StreamTransformationFilter(e, new StringSink(ciphertext)));
}

void aes_decrypt(const SecByteBlock& key, const std::string& ciphertext, std::string& plaintext) {
    byte iv[AES::BLOCKSIZE] = {0};
    try {
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, sizeof(iv));
        StringSource(ciphertext, true, new StreamTransformationFilter(d, new StringSink(plaintext)));
    } catch(const Exception&) {
        plaintext = ""; // Decryption failure
    }
}

// --- Player State ---
struct Player {
    int id;
    std::string user_id_str;
    std::string nonce;
    SecByteBlock sym_key; // ki

    Integer x_i;
    ECPPoint z_i;
    std::string z_i_star;

    ECPPoint Z_i;
    ECPPoint Z_i_plus_1;
    ECPPoint X_i;

    ECPPoint K_i; // Intermediate key
    std::string auth_i;
    std::string session_key; // ski
};

int main() {
    AutoSeededRandomPool prng;

    // =================================================================
    // 1. SETUP PHASE
    // =================================================================
    auto setup_start = std::chrono::high_resolution_clock::now();

    const int n = NUM_PARTICIPANTS;
    std::vector<Player> players(n);

    // Cryptographic parameters
    DL_GroupParameters_EC<ECP> params(ASN1::secp256r1());
    const ECPPoint& g = params.GetSubgroupGenerator();
    const Integer& q = params.GetSubgroupOrder();
    std::string password = "a-secure-shared-password";

    auto setup_end = std::chrono::high_resolution_clock::now();


    // =================================================================
    // 2. KEY EXCHANGE PHASE
    // =================================================================
    auto exchange_start = std::chrono::high_resolution_clock::now();
    
    // --- ROUND 1: Broadcast nonces ---
    for (int i = 0; i < n; ++i) {
        players[i].id = i;
        players[i].user_id_str = "User" + std::to_string(i);
        
        SecByteBlock nonce_bytes(16);
        prng.GenerateBlock(nonce_bytes, nonce_bytes.size());
        StringSource(nonce_bytes, nonce_bytes.size(), true, new HexEncoder(new StringSink(players[i].nonce)));
    }

    // --- ROUND 2: Define session, derive keys, broadcast encrypted z_i ---
    std::string session_id;
    for (int i = 0; i < n; ++i) {
        session_id += players[i].user_id_str + players[i].nonce;
    }

    for (int i = 0; i < n; ++i) {
        players[i].sym_key = derive_symmetric_key(session_id, i, password);
        players[i].x_i.Randomize(prng, Integer::One(), q - 1);
        players[i].z_i = params.ExponentiateBase(players[i].x_i);
        aes_encrypt(players[i].sym_key, ECPPointToString(params, players[i].z_i), players[i].z_i_star);
    }

   // --- ROUND 3: Decrypt neighbors, compute and broadcast Xi ---
for (int i = 0; i < n; ++i) {
    int i_minus_1 = (i == 0) ? n - 1 : i - 1;
    int i_plus_1 = (i == n - 1) ? 0 : i + 1;

    // Decrypt z* of neighbors
    std::string z_minus_1_str, z_plus_1_str;
    aes_decrypt(players[i_minus_1].sym_key, players[i_minus_1].z_i_star, z_minus_1_str);
    aes_decrypt(players[i_plus_1].sym_key, players[i_plus_1].z_i_star, z_plus_1_str);
    
    ECPPoint z_i_minus_1, z_i_plus_1;
    StringSource ss_minus_1(z_minus_1_str, true);
    params.GetCurve().DecodePoint(z_i_minus_1, ss_minus_1, ss_minus_1.MaxRetrievable());
    StringSource ss_plus_1(z_plus_1_str, true);
    params.GetCurve().DecodePoint(z_i_plus_1, ss_plus_1, ss_plus_1.MaxRetrievable());
    
    // ================== CORRECTED LOGIC START ==================
    // Correctly compute Zi and Z_{i+1} from player i's perspective
    // Zi is computed with the left neighbor (i-1)
    players[i].Z_i = params.ExponentiateElement(z_i_minus_1, players[i].x_i);
    
    // Z_{i+1} is computed with the right neighbor (i+1). 
    // This requires z_i and the neighbor's private key x_{i+1}
    // In our simulation, we access it directly to model the computation cost.
    players[i].Z_i_plus_1 = params.ExponentiateElement(players[i].z_i, players[i_plus_1].x_i);
    // =================== CORRECTED LOGIC END ===================

    // Broadcast Xi = Z_{i+1} / Zi (in additive group: Z_{i+1} - Zi)
    players[i].X_i = params.GetCurve().Add(players[i].Z_i_plus_1, params.GetCurve().Inverse(players[i].Z_i));
}
    
    // --- ROUND 4: Compute intermediate key Ki and broadcast confirmation Auth_i ---
    std::string round4_payload_base = session_id;
    for(int i = 0; i < n; ++i) { round4_payload_base += players[i].z_i_star + ECPPointToString(params, players[i].X_i); }

    for (int i = 0; i < n; ++i) {
        players[i].K_i = params.GetCurve().ScalarMultiply(players[i].Z_i, n);
        for(int j = 1; j < n; ++j) {
            int player_idx = (i + j - 1) % n;
            int exponent = n - j;
            if (exponent > 0) {
                ECPPoint term = params.GetCurve().ScalarMultiply(players[player_idx].X_i, exponent);
                players[i].K_i = params.GetCurve().Add(players[i].K_i, term);
            }
        }
        players[i].auth_i = sha256_hash(round4_payload_base + ECPPointToString(params, players[i].K_i) + std::to_string(i));
    }
    
    // --- ROUND 5: Verify confirmations and compute final session key ski ---
    std::string round5_payload_base = session_id;
    for(int i = 0; i < n; ++i) { round5_payload_base += players[i].z_i_star + ECPPointToString(params, players[i].X_i) + players[i].auth_i; }

    for (int i = 0; i < n; ++i) {
        players[i].session_key = sha256_hash(round5_payload_base + ECPPointToString(params, players[i].K_i));
    }

    auto exchange_end = std::chrono::high_resolution_clock::now();

    // =================================================================
    // 3. OUTPUT RESULTS & VERIFICATION
    // =================================================================
    
    // Calculate durations
    std::chrono::duration<double, std::milli> setup_duration = setup_end - setup_start;
    std::chrono::duration<double, std::milli> exchange_duration = exchange_end - exchange_start;

    // Print timing info for the script
    std::cout << "Total Setup computation time: " << setup_duration.count() << " ms" << std::endl;
    std::cout << "Total Key Exchange computation time: " << exchange_duration.count() << " ms" << std::endl;

    // Optional: Print verification status to standard error so it doesn't interfere with script parsing
    bool success = true;
    for (int i = 1; i < n; ++i) {
        if (players[i].session_key != players[0].session_key) {
            success = false;
            break;
        }
    }
    if (!success) {
        std::cerr << "❌ 协议失败: 参与方未能达成一致的密钥。" << std::endl;
    }

    return 0;
}
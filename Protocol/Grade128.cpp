#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <map>
#include <tuple>
#include <sstream>

// Crypto++ Headers
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>      // <-- 修改: 使用 SHA256
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>    // <-- 修改: 包含 CBC 模式的头文件
#include <cryptopp/filters.h>  // <-- 修改: 包含 StreamTransformationFilter 的头文件
#include <cryptopp/misc.h>
#include <cryptopp/ecp.h>

using namespace CryptoPP;
using Point = ECP::Point;
struct CryptoPrimitives; // Forward declaration for CryptoPrimitives

// ------------------------------------------------------------------
//                             辅助函数和结构体
// ------------------------------------------------------------------

// 将一个点转换为十六进制字符串 "HEX(x)|HEX(y)"
std::string PointToString(const Point& p) {
    if (p.identity) return "IDENTITY|IDENTITY";
    
    std::string hex_x, hex_y;
    HexEncoder hex_enc_x(new StringSink(hex_x));
    p.x.Encode(hex_enc_x, p.x.ByteCount());
    hex_enc_x.MessageEnd();

    HexEncoder hex_enc_y(new StringSink(hex_y));
    p.y.Encode(hex_enc_y, p.y.ByteCount());
    hex_enc_y.MessageEnd();

    return hex_x + "|" + hex_y;
}

// 通过分隔符分割字符串
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// 从两个十六进制字符串反序列化一个点
Point StringToPoint(const ECP& curve, const std::string& hex_x, const std::string& hex_y) {
    Point p;
    p.identity = false;

    std::string decoded_x, decoded_y;
    StringSource ss_x(hex_x, true, new HexDecoder(new StringSink(decoded_x)));
    StringSource ss_y(hex_y, true, new HexDecoder(new StringSink(decoded_y)));

    p.x.Decode((const byte*)decoded_x.data(), decoded_x.size());
    p.y.Decode((const byte*)decoded_y.data(), decoded_y.size());

    if (!curve.VerifyPoint(p)) {
        throw std::runtime_error("Failed to deserialize a valid point.");
    }
    return p;
}


// 用于保存 f_i 消息解析后内容的结构体
struct DecryptedFMessage {
    std::string ssid;
    std::string id;
    Point X;
    std::string enc_R_hex; // R 现在被加密并以十六进制编码
    std::string c;
};

// Promitives 结构体
struct CryptoPrimitives {
    DL_GroupParameters_EC<ECP> params;
    const ECP& curve;
    const Integer& groupOrder;
    const Point& generator;

    CryptoPrimitives() : 
        params(ASN1::secp256r1()), // <-- 修改: 使用 256-bit 椭圆曲线
        curve(params.GetCurve()),
        groupOrder(params.GetSubgroupOrder()),
        generator(params.GetSubgroupGenerator())
    {}

    // SHA-256
    std::string Hash(const std::string& input) {
        SHA256 hash; // <-- 修改: 使用 SHA256
        std::string digest;
        StringSource(input, true, new HashFilter(hash, new StringSink(digest)));
        return digest;
    }

    Integer H1(const std::string& sid, const std::string& pi) {
        std::string digest = Hash(sid + pi);
        return Integer((const byte*)digest.data(), digest.size()) % groupOrder;
    }


    // 使用 AES-128-CBC 加密和解密
    std::string Encrypt(const SecByteBlock& key, const std::string& plaintext) {
        CBC_Mode<AES>::Encryption e;
        SecByteBlock iv(AES::BLOCKSIZE);
        AutoSeededRandomPool prng;
        prng.GenerateBlock(iv, iv.size());
        std::string ciphertext;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());
        StringSource(plaintext, true, new StreamTransformationFilter(e, new StringSink(ciphertext)));
        return std::string((char*)iv.begin(), iv.size()) + ciphertext;
    }

    std::string Decrypt(const SecByteBlock& key, const std::string& iv_and_ciphertext) {
        if (iv_and_ciphertext.size() < AES::BLOCKSIZE) throw std::runtime_error("Invalid ciphertext size.");
        SecByteBlock iv((const byte*)iv_and_ciphertext.data(), AES::BLOCKSIZE);
        std::string ciphertext = iv_and_ciphertext.substr(AES::BLOCKSIZE);
        CBC_Mode<AES>::Decryption d;
        std::string decryptedtext;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());
        StringSource(ciphertext, true, new StreamTransformationFilter(d, new StringSink(decryptedtext)));
        return decryptedtext;
    }

    Point AddPoints(const Point& p1, const Point& p2) { return curve.Add(p1, p2); }
    Point ScalarMultiply(const Integer& s) { return curve.ScalarMultiply(generator, s); }
    Point ScalarMultiply(const Point& p, const Integer& s) { return curve.ScalarMultiply(p, s); }
    Point InvertPoint(const Point& p) { return curve.Inverse(p); }
};

// 对应 FILE[sid]
struct PasswordFile {
    std::string id;
    Point X_i;
    Point Y_i;
    Integer x_hat_i;
    std::string hpw_i;
};

// 协议各轮次广播的消息结构体
struct Broadcast_f { std::string from_id; std::string f_i; };
struct Broadcast_Alpha_X { std::string from_id; Point alpha_i; Point X_prime_i; };
struct Broadcast_Auth { std::string from_id; std::string auth_i; };



// ------------------------------------------------------------------
//                             Participant 类
// ------------------------------------------------------------------
class Participant {
public:
    std::string id;
    std::string password; //pi
    std::string sid;
    std::string ssid;

    CryptoPrimitives crypto;
    PasswordFile my_file;

    // 内部状态
    Integer r_i;
    Point R_i;
    SecByteBlock k_i;
    Point my_A_i;
    Point my_beta_i;


    // 存储从其他参与方收到的信息
    std::map<std::string, PasswordFile> other_files;
    std::map<std::string, Point> received_R;
    std::map<std::string, Point> received_alpha;
    std::map<std::string, Point> received_X_prime;
    
    std::string session_key; // 最终会话密钥

    Participant(std::string participant_id, std::string pwd, std::string session_id)
        : id(std::move(participant_id)), password(std::move(pwd)), sid(std::move(session_id)) {
        ssid = "ssid_project_x_2025";
    }

    // 对应 V.B. Setup 阶段
    void Setup() {
        AutoSeededRandomPool prng;
        Integer x_i;
        x_i.Randomize(prng, Integer::One(), crypto.groupOrder - 1);
        my_file.X_i = crypto.ScalarMultiply(x_i);
        Integer y_i = crypto.H1(sid, password);
        my_file.Y_i = crypto.ScalarMultiply(y_i);
        std::string h_i_str = crypto.Hash(sid + id + PointToString(my_file.X_i));
        Integer h_i((const byte*)h_i_str.data(), h_i_str.size());
        my_file.x_hat_i = (x_i + y_i * h_i) % crypto.groupOrder;
        my_file.hpw_i = crypto.Hash(password);
        my_file.id = id;
    }

    // 轮次 1: 生成并广播 f_i
    Broadcast_f round1_generate_f() {
        AutoSeededRandomPool prng;
        r_i.Randomize(prng, Integer::One(), crypto.groupOrder - 1);
        R_i = crypto.ScalarMultiply(r_i);
        std::string k_i_str = crypto.Hash(ssid + id + my_file.hpw_i);
        k_i = SecByteBlock((const byte*)k_i_str.data(), 16); // 密钥长度 16 字节 (128-bit for AES-128)
        
        std::string y_prime_i_str = crypto.Hash(PointToString(my_file.Y_i) + id);
        SecByteBlock k_R_i((const byte*)y_prime_i_str.data(), 16); // 密钥长度 16 字节
        std::string r_i_as_string = PointToString(R_i);
        std::string enc_R_i = crypto.Encrypt(k_R_i, r_i_as_string);

        std::string enc_R_i_hex;
        StringSource(enc_R_i, true, new HexEncoder(new StringSink(enc_R_i_hex)));
        
        std::string c_i_raw = crypto.Hash(ssid + PointToString(my_file.X_i) + id);
        std::string c_i_hex;
        StringSource(c_i_raw, true, new HexEncoder(new StringSink(c_i_hex)));

        std::string plaintext_for_f = ssid + "|" + id + "|" + PointToString(my_file.X_i) + "|" + enc_R_i_hex + "|" + c_i_hex;
        std::string f_i = crypto.Encrypt(k_i, plaintext_for_f);
        return {id, f_i};
    }

    // 轮次 2: 处理 f 消息, 生成并广播 alpha_i 和 X_prime_i
    Broadcast_Alpha_X round2_generate_alpha_X(
        const Broadcast_f& f_prev, 
        const Broadcast_f& f_next, 
        const std::map<std::string, PasswordFile>& all_files
    ) {
        other_files = all_files;

        const PasswordFile& file_prev = all_files.at(f_prev.from_id);
        const PasswordFile& file_next = all_files.at(f_next.from_id);
        std::string k_prev_str = crypto.Hash(ssid + file_prev.id + file_prev.hpw_i);
        SecByteBlock k_prev((const byte*)k_prev_str.data(), 16); // 密钥长度 16 字节
        std::string df_prev_str = crypto.Decrypt(k_prev, f_prev.f_i);
        std::string k_next_str = crypto.Hash(ssid + file_next.id + file_next.hpw_i);
        SecByteBlock k_next((const byte*)k_next_str.data(), 16); // 密钥长度 16 字节
        std::string df_next_str = crypto.Decrypt(k_next, f_next.f_i);
        std::cout << "      (" << id << ") Successfully decrypted messages from " << file_prev.id << " and " << file_next.id << ".\n";

        auto parse_message = [&](const std::string& decrypted_payload) -> DecryptedFMessage {
            std::vector<std::string> parts = split(decrypted_payload, '|');
            if (parts.size() != 6) {
                throw std::runtime_error("Invalid message format: expected 6 parts, got " + std::to_string(parts.size()));
            }
            DecryptedFMessage msg;
            msg.ssid = parts[0];
            msg.id = parts[1];
            msg.X = StringToPoint(crypto.curve, parts[2], parts[3]);
            msg.enc_R_hex = parts[4];
            msg.c = parts[5];
            return msg;
        };
        DecryptedFMessage msg_prev = parse_message(df_prev_str);
        DecryptedFMessage msg_next = parse_message(df_next_str);
        std::cout << "      (" << id << ") Parsed message contents from neighbors.\n";

        std::string expected_c_prev_raw = crypto.Hash(ssid + PointToString(msg_prev.X) + msg_prev.id);
        std::string expected_c_prev_hex;
        StringSource(expected_c_prev_raw, true, new HexEncoder(new StringSink(expected_c_prev_hex)));
        if (expected_c_prev_hex != msg_prev.c) throw std::runtime_error("c value check failed for " + msg_prev.id + "! Aborting.");
        
        std::string expected_c_next_raw = crypto.Hash(ssid + PointToString(msg_next.X) + msg_next.id);
        std::string expected_c_next_hex;
        StringSource(expected_c_next_raw, true, new HexEncoder(new StringSink(expected_c_next_hex)));
        if (expected_c_next_hex != msg_next.c) throw std::runtime_error("c value check failed for " + msg_next.id + "! Aborting.");

        std::cout << "      (" << id << ") Integrity checks for c_prev and c_next passed.\n";

        auto decrypt_and_store_R = [&](const DecryptedFMessage& msg, const PasswordFile& file) {
            std::string y_prime_str = crypto.Hash(PointToString(file.Y_i) + file.id);
            SecByteBlock k_R((const byte*)y_prime_str.data(), 16); // 密钥长度 16 字节

            std::string enc_R;
            StringSource(msg.enc_R_hex, true, new HexDecoder(new StringSink(enc_R)));

            std::string r_str = crypto.Decrypt(k_R, enc_R);
            
            std::vector<std::string> r_parts = split(r_str, '|');
            if (r_parts.size() != 2) throw std::runtime_error("Invalid decrypted R format for " + file.id);
            Point R = StringToPoint(crypto.curve, r_parts[0], r_parts[1]);
            
            received_R[file.id] = R;
        };

        decrypt_and_store_R(msg_prev, file_prev);
        decrypt_and_store_R(msg_next, file_next);
        std::cout << "      (" << id << ") Successfully decrypted and retrieved R values from neighbors.\n";

        std::string h_prev_str = crypto.Hash(sid + file_prev.id + PointToString(file_prev.X_i));
        Integer h_prev((const byte*)h_prev_str.data(), h_prev_str.size());
        std::string h_next_str = crypto.Hash(sid + file_next.id + PointToString(file_next.X_i));
        Integer h_next((const byte*)h_next_str.data(), h_next_str.size());
        
        Point R_next_div_R_prev = crypto.AddPoints(received_R.at(file_next.id), crypto.InvertPoint(received_R.at(file_prev.id)));
        Point alpha_i = crypto.ScalarMultiply(R_next_div_R_prev, r_i);

        Point term1 = crypto.AddPoints(received_R.at(file_next.id), file_next.X_i);
        Point term2 = crypto.ScalarMultiply(file_next.Y_i, h_next);
        Point numerator_base = crypto.AddPoints(term1, term2);
        Point term3 = crypto.AddPoints(received_R.at(file_prev.id), file_prev.X_i);
        Point term4 = crypto.ScalarMultiply(file_prev.Y_i, h_prev);
        Point denominator_base = crypto.AddPoints(term3, term4);
        Point base = crypto.AddPoints(numerator_base, crypto.InvertPoint(denominator_base));
        Integer exponent = (r_i + my_file.x_hat_i) % crypto.groupOrder;
        Point X_prime_i = crypto.ScalarMultiply(base, exponent);

        return {id, alpha_i, X_prime_i};
    }

    Broadcast_Auth round3_compute_auth(
        const std::vector<Broadcast_Alpha_X>& all_alpha_X,
        const std::vector<std::string>& participant_order
    ) {
        size_t n = participant_order.size();
        for(const auto& msg : all_alpha_X) {
            received_alpha[msg.from_id] = msg.alpha_i;
            received_X_prime[msg.from_id] = msg.X_prime_i;
        }
        size_t my_idx = 0;
        for(size_t i=0; i<n; ++i) if(participant_order[i] == id) my_idx = i;
        
        const std::string& prev_id_for_R = participant_order[(my_idx + n - 1) % n];
        my_A_i = crypto.ScalarMultiply(received_R.at(prev_id_for_R), Integer(n) * r_i);
        for(size_t j=1; j < n; ++j) {
            const std::string& current_id = participant_order[(my_idx + j - 1) % n];
            Point term = crypto.ScalarMultiply(received_alpha.at(current_id), Integer(n - j));
            my_A_i = crypto.AddPoints(my_A_i, term);
        }

        const auto& prev_file = other_files.at(prev_id_for_R);
        std::string h_prev_str = crypto.Hash(sid + prev_file.id + PointToString(prev_file.X_i));
        Integer h_prev((const byte*)h_prev_str.data(), h_prev_str.size());
        Point beta_base = crypto.AddPoints(received_R.at(prev_id_for_R), prev_file.X_i);
        beta_base = crypto.AddPoints(beta_base, crypto.ScalarMultiply(prev_file.Y_i, h_prev));
        my_beta_i = crypto.ScalarMultiply(beta_base, Integer(n) * (r_i + my_file.x_hat_i));
        for (size_t j = 1; j < n; ++j) {
            const std::string& current_id = participant_order[(my_idx + j - 1) % n];
            Point term = crypto.ScalarMultiply(received_X_prime.at(current_id), Integer(n - j));
            my_beta_i = crypto.AddPoints(my_beta_i, term);
        }
        
        std::string auth_i_payload = ssid + PointToString(my_A_i) + PointToString(my_beta_i) + id;
        std::string auth_i = crypto.Hash(auth_i_payload);
        
        return {id, auth_i};
    }

    void round4_verify_auths_and_finalize(
        const std::map<std::string, Broadcast_Auth>& all_auths,
        const std::map<std::string, Broadcast_f>& all_f_messages,
        const std::vector<std::string>& participant_order
    ) {
        for(const auto& p : all_auths) {
            const std::string& other_id = p.first;
            const std::string& received_auth = p.second.auth_i;
            
            if (other_id == id) continue;

            std::string expected_auth_payload = ssid + PointToString(my_A_i) + PointToString(my_beta_i) + other_id;
            std::string expected_auth = crypto.Hash(expected_auth_payload);

            if (expected_auth != received_auth) {
                throw std::runtime_error("Auth verification failed for participant " + other_id + "! Protocol aborted.");
            }
        }
        
        std::cout << "      (" << id << ") Successfully verified all received authentication tags.\n";

        std::string sk_payload = sid;
        for(const auto& pid : participant_order) {
            sk_payload += all_f_messages.at(pid).f_i + PointToString(received_alpha.at(pid)) + PointToString(received_X_prime.at(pid));
        }
        sk_payload += PointToString(my_A_i) + PointToString(my_beta_i);
        session_key = crypto.Hash(sk_payload);
    }
};


// ------------------------------------------------------------------
//                             主函数 (网络模拟器)
// ------------------------------------------------------------------
int main() {
    try {
        const int NUM_PARTICIPANTS = 3;
        std::string session_id = "SID_secure_IoT_2025";
        std::vector<std::string> p_order;
        for (int i = 1; i <= NUM_PARTICIPANTS; ++i) {
            p_order.push_back("P" + std::to_string(i));
        }

        std::cout << "--- Initialization ---\n";
        std::map<std::string, Participant> participants;
        for (int i = 1; i <= NUM_PARTICIPANTS; ++i) {
            std::string id = "P" + std::to_string(i);
            std::string pass = "password_" + std::to_string(i);
            participants.emplace(std::piecewise_construct, 
                                 std::forward_as_tuple(id), 
                                 std::forward_as_tuple(id, pass, session_id));
        }
        std::cout << NUM_PARTICIPANTS << " participants created.\n\n";

        // === SETUP 阶段 ===
        std::cout << "--- Phase 1: SETUP ---\n";
        std::map<std::string, PasswordFile> all_files;
        for (const auto& id : p_order) {
            participants.at(id).Setup();
            all_files[id] = participants.at(id).my_file;
            std::cout << "Participant " << id << " completed Setup.\n";
        }
        std::cout << "All password files generated.\n\n";

        // === 密钥交换 ===
        // --- 轮次 1: 广播 f_i ---
        std::cout << "--- Phase 2: Key Exchange (Round 1) ---\n";
        std::map<std::string, Broadcast_f> round1_messages;
        for (const auto& id : p_order) {
            round1_messages[id] = participants.at(id).round1_generate_f();
            std::cout << "Participant " << id << " generated and broadcasted f_" << id.substr(1) << ".\n";
        }
        std::cout << "Round 1 broadcast complete.\n\n";
        
        // --- 轮次 2: 广播 alpha_i, X'_i ---
        std::cout << "--- Phase 2: Key Exchange (Round 2) ---\n";
        std::map<std::string, Broadcast_Alpha_X> round2_messages;
        for (size_t i = 0; i < NUM_PARTICIPANTS; ++i) {
            const auto& current_id = p_order[i];
            const auto& prev_id = p_order[(i + NUM_PARTICIPANTS - 1) % NUM_PARTICIPANTS];
            const auto& next_id = p_order[(i + 1) % NUM_PARTICIPANTS];
            std::cout << "   > Participant " << current_id << " is processing messages from " << prev_id << " and " << next_id << "...\n";
            round2_messages[current_id] = participants.at(current_id).round2_generate_alpha_X(
                round1_messages.at(prev_id), round1_messages.at(next_id), all_files
            );
            std::cout << "Participant " << current_id << " generated and broadcasted alpha_" << current_id.substr(1)
                      << " and X_prime_" << current_id.substr(1) << ".\n";
        }
        std::cout << "Round 2 broadcast complete.\n\n";

        // --- 轮次 3: 计算并广播 Auth_i ---
        std::cout << "--- Phase 2: Key Exchange (Round 3) ---\n";
        std::vector<Broadcast_Alpha_X> r2_msg_vec;
        for(const auto& id : p_order) r2_msg_vec.push_back(round2_messages.at(id));
        std::map<std::string, Broadcast_Auth> round3_messages;
        for (const auto& id : p_order) {
            std::cout << "Participant " << id << " is computing A and beta values...\n";
            round3_messages[id] = participants.at(id).round3_compute_auth(r2_msg_vec, p_order);
            std::cout << "Participant " << id << " computed and broadcasted Auth_" << id.substr(1) << ".\n";
        }
        std::cout << "Round 3 broadcast complete.\n\n";

        // --- 轮次 4: 验证 Auth 并最终计算 SK ---
        std::cout << "--- Phase 2: Key Exchange (Round 4) ---\n";
        for (const auto& id : p_order) {
             std::cout << "   > Participant " << id << " is verifying all received Auth messages...\n";
             participants.at(id).round4_verify_auths_and_finalize(round3_messages, round1_messages, p_order);
             std::cout << "Participant " << id << " successfully verified and computed the final session key.\n";
        }
        std::cout << "Round 4 verification and finalization complete.\n\n";


        // --- 最终验证 ---
        std::cout << "--- Final Verification ---\n";
        std::string first_key;
        bool all_keys_match = true;
        for(size_t i=0; i<p_order.size(); ++i) {
            const auto& id = p_order[i];
            std::string current_key_str;
            StringSource(participants.at(id).session_key, true, new HexEncoder(new StringSink(current_key_str)));
            std::cout << "Participant " << id << "'s final key: " << current_key_str << "\n";
            if (i == 0) {
                first_key = participants.at(id).session_key;
            } else {
                if (first_key != participants.at(id).session_key) {
                    all_keys_match = false;
                }
            }
        }
        std::cout << "\n";

        if (all_keys_match) {
            std::cout << "✅ SUCCESS: All participants computed the same session key.\n";
        } else {
            std::cout << "❌ FAILURE: Session keys do not match!\n";
        }

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
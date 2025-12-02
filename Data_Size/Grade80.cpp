#include <iostream>
#include <vector>
#include <string>
#include <stdexcept>
#include <map>
#include <tuple>
#include <sstream>
#include <chrono>

// Crypto++ Headers
#include <cryptopp/osrng.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/integer.h>
#include <cryptopp/des.h>       // <-- 恢复: 使用 DES
#include <cryptopp/modes.h>     // <-- 恢复: 包含 CBC 模式的头文件
#include <cryptopp/filters.h>   // <-- 恢复: 包含 StreamTransformationFilter 的头文件
#include <cryptopp/misc.h>
#include <cryptopp/ecp.h>

using namespace CryptoPP;
using Point = ECP::Point;
struct CryptoPrimitives; // Forward declaration for CryptoPrimitives

// ------------------------------------------------------------------
//                          辅助函数和结构体
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
        params(ASN1::secp160r1()), // <-- 恢复: 160-bit 椭圆曲线 (80-bit security)
        curve(params.GetCurve()),
        groupOrder(params.GetSubgroupOrder()),
        generator(params.GetSubgroupGenerator())
    {}

    // SHA-1
    std::string Hash(const std::string& input) {
        SHA1 hash; // <-- 恢复: SHA-1 (80-bit security)
        std::string digest;
        StringSource(input, true, new HashFilter(hash, new StringSink(digest)));
        return digest;
    }

    Integer H1(const std::string& sid, const std::string& pi) {
        std::string digest = Hash(sid + pi);
        return Integer((const byte*)digest.data(), digest.size()) % groupOrder;
    }


    // 使用 2TDEA-CBC 加密和解密
    std::string Encrypt(const SecByteBlock& key, const std::string& plaintext) {
        CBC_Mode<DES_EDE2>::Encryption e; // <-- 恢复: 使用 CBC 模式
        SecByteBlock iv(DES_EDE2::BLOCKSIZE); // IV 尺寸为 8 字节
        AutoSeededRandomPool prng;
        prng.GenerateBlock(iv, iv.size());
        std::string ciphertext;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());
        // <-- 恢复: 使用 StreamTransformationFilter 进行非认证加密
        StringSource(plaintext, true, new StreamTransformationFilter(e, new StringSink(ciphertext)));
        return std::string((char*)iv.begin(), iv.size()) + ciphertext;
    }

    std::string Decrypt(const SecByteBlock& key, const std::string& iv_and_ciphertext) {
        if (iv_and_ciphertext.size() < DES_EDE2::BLOCKSIZE) throw std::runtime_error("Invalid ciphertext size.");
        SecByteBlock iv((const byte*)iv_and_ciphertext.data(), DES_EDE2::BLOCKSIZE);
        std::string ciphertext = iv_and_ciphertext.substr(DES_EDE2::BLOCKSIZE);
        CBC_Mode<DES_EDE2>::Decryption d; // <-- 恢复: 使用 CBC 模式
        std::string decryptedtext;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());
        // <-- 恢复: 使用 StreamTransformationFilter 进行非认证解密
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
//                          Participant 类
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
    Point my_A_i;       // 【新增】暂存自己计算的 A_i
    Point my_beta_i;    // 【新增】暂存自己计算的 beta_i


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
        my_file.X_i = crypto.ScalarMultiply(x_i); // (1)
        Integer y_i = crypto.H1(sid, password); // (2)
        my_file.Y_i = crypto.ScalarMultiply(y_i); // (3)
        std::string h_i_str = crypto.Hash(sid + id + PointToString(my_file.X_i)); // (4)
        Integer h_i((const byte*)h_i_str.data(), h_i_str.size());
        my_file.x_hat_i = (x_i + y_i * h_i) % crypto.groupOrder; // (5)
        my_file.hpw_i = crypto.Hash(password); // (6)
        my_file.id = id; // (7)
    }

    // 轮次 1: 生成并广播 f_i
    Broadcast_f round1_generate_f() {
        AutoSeededRandomPool prng;
        r_i.Randomize(prng, Integer::One(), crypto.groupOrder - 1); // (2)
        R_i = crypto.ScalarMultiply(r_i); // (2)
        std::string k_i_str = crypto.Hash(ssid + id + my_file.hpw_i); // (3)
        k_i = SecByteBlock((const byte*)k_i_str.data(), 16); // <-- 恢复: 密钥长度为 16 字节 (128-bit for 2TDEA)
        
        // 使用派生密钥 Y_i' = H(Y_i, id_i) 来加密 R_i
        std::string y_prime_i_str = crypto.Hash(PointToString(my_file.Y_i) + id);
        SecByteBlock k_R_i((const byte*)y_prime_i_str.data(), 16); // <-- 恢复: 密钥长度为 16 字节
        std::string r_i_as_string = PointToString(R_i);
        std::string enc_R_i = crypto.Encrypt(k_R_i, r_i_as_string);

        // 将加密后的 R_i 进行十六进制编码，以安全地包含在以'|'分割的字符串中
        std::string enc_R_i_hex;
        StringSource(enc_R_i, true, new HexEncoder(new StringSink(enc_R_i_hex)));
        
        // 对 c_i 哈希值进行十六进制编码
        std::string c_i_raw = crypto.Hash(ssid + PointToString(my_file.X_i) + id); // (4)
        std::string c_i_hex;
        StringSource(c_i_raw, true, new HexEncoder(new StringSink(c_i_hex)));

        // 新的消息格式: ssid|id|X_hex_x|X_hex_y|enc_R_i_hex|c_hex
        std::string plaintext_for_f = ssid + "|" + id + "|" + PointToString(my_file.X_i) + "|" + enc_R_i_hex + "|" + c_i_hex; // (5)
        std::string f_i = crypto.Encrypt(k_i, plaintext_for_f); // (5)
        return {id, f_i};
    }

    // 轮次 2: 处理 f 消息, 生成并广播 alpha_i 和 X_prime_i
    Broadcast_Alpha_X round2_generate_alpha_X(
        const Broadcast_f& f_prev, 
        const Broadcast_f& f_next, 
        const std::map<std::string, PasswordFile>& all_files
    ) {
        other_files = all_files;

        // (6) 检索并解密 f_i-1 和 f_i+1
        const PasswordFile& file_prev = all_files.at(f_prev.from_id);
        const PasswordFile& file_next = all_files.at(f_next.from_id);
        std::string k_prev_str = crypto.Hash(ssid + file_prev.id + file_prev.hpw_i);
        SecByteBlock k_prev((const byte*)k_prev_str.data(), 16); // <-- 恢复: 密钥长度为 16 字节
        std::string df_prev_str = crypto.Decrypt(k_prev, f_prev.f_i);
        std::string k_next_str = crypto.Hash(ssid + file_next.id + file_next.hpw_i);
        SecByteBlock k_next((const byte*)k_next_str.data(), 16); // <-- 恢复: 密钥长度为 16 字节
        std::string df_next_str = crypto.Decrypt(k_next, f_next.f_i);

        // (7) 从解密后的消息中解析 ssid, id, X, enc_R_hex, c
        auto parse_message = [&](const std::string& decrypted_payload) -> DecryptedFMessage {
            std::vector<std::string> parts = split(decrypted_payload, '|');
            if (parts.size() != 6) { // 期望6个部分: ssid|id|X.x|X.y|enc_R_hex|c_hex
                throw std::runtime_error("Invalid message format: expected 6 parts, got " + std::to_string(parts.size()));
            }
            DecryptedFMessage msg;
            msg.ssid = parts[0];
            msg.id = parts[1];
            msg.X = StringToPoint(crypto.curve, parts[2], parts[3]);
            msg.enc_R_hex = parts[4];
            msg.c = parts[5]; // c 已经是十六进制编码的字符串
            return msg;
        };
        DecryptedFMessage msg_prev = parse_message(df_prev_str);
        DecryptedFMessage msg_next = parse_message(df_next_str);

        // (8) 检查 c_i-1 和 c_i+1
        std::string expected_c_prev_raw = crypto.Hash(ssid + PointToString(msg_prev.X) + msg_prev.id);
        std::string expected_c_prev_hex;
        StringSource(expected_c_prev_raw, true, new HexEncoder(new StringSink(expected_c_prev_hex)));
        if (expected_c_prev_hex != msg_prev.c) throw std::runtime_error("c value check failed for " + msg_prev.id + "! Aborting.");
        
        std::string expected_c_next_raw = crypto.Hash(ssid + PointToString(msg_next.X) + msg_next.id);
        std::string expected_c_next_hex;
        StringSource(expected_c_next_raw, true, new HexEncoder(new StringSink(expected_c_next_hex)));
        if (expected_c_next_hex != msg_next.c) throw std::runtime_error("c value check failed for " + msg_next.id + "! Aborting.");

        // (9) 使用 Y'_j = H(Y_j, id_j) 作为密钥来解密 R_j
        auto decrypt_and_store_R = [&](const DecryptedFMessage& msg, const PasswordFile& file) {
            // 重构密钥 Y_j' = H(Y_j, id_j)
            std::string y_prime_str = crypto.Hash(PointToString(file.Y_i) + file.id);
            SecByteBlock k_R((const byte*)y_prime_str.data(), 16); // <-- 恢复: 密钥长度为 16 字节

            // 从消息中十六进制解码加密的 R_j
            std::string enc_R;
            StringSource(msg.enc_R_hex, true, new HexDecoder(new StringSink(enc_R)));

            // 解密得到 R_j 的字符串形式 "x|y"
            std::string r_str = crypto.Decrypt(k_R, enc_R);
            
            // 将字符串解析回 ECP::Point
            std::vector<std::string> r_parts = split(r_str, '|');
            if (r_parts.size() != 2) throw std::runtime_error("Invalid decrypted R format for " + file.id);
            Point R = StringToPoint(crypto.curve, r_parts[0], r_parts[1]);
            
            // 存储恢复出的点
            received_R[file.id] = R;
        };

        decrypt_and_store_R(msg_prev, file_prev);
        decrypt_and_store_R(msg_next, file_next);

        // (10) 计算 h_i-1 和 h_i+1
        std::string h_prev_str = crypto.Hash(sid + file_prev.id + PointToString(file_prev.X_i));
        Integer h_prev((const byte*)h_prev_str.data(), h_prev_str.size());
        std::string h_next_str = crypto.Hash(sid + file_next.id + PointToString(file_next.X_i));
        Integer h_next((const byte*)h_next_str.data(), h_next_str.size());
        
        // (11) 计算 alpha_i
        Point R_next_div_R_prev = crypto.AddPoints(received_R.at(file_next.id), crypto.InvertPoint(received_R.at(file_prev.id)));
        Point alpha_i = crypto.ScalarMultiply(R_next_div_R_prev, r_i);

        // (12) 计算 X'_i
        Point term1 = crypto.AddPoints(received_R.at(file_next.id), file_next.X_i);
        Point term2 = crypto.ScalarMultiply(file_next.Y_i, h_next);
        Point numerator_base = crypto.AddPoints(term1, term2);
        Point term3 = crypto.AddPoints(received_R.at(file_prev.id), file_prev.X_i);
        Point term4 = crypto.ScalarMultiply(file_prev.Y_i, h_prev);
        Point denominator_base = crypto.AddPoints(term3, term4);
        Point base = crypto.AddPoints(numerator_base, crypto.InvertPoint(denominator_base));
        Integer exponent = (r_i + my_file.x_hat_i) % crypto.groupOrder;
        Point X_prime_i = crypto.ScalarMultiply(base, exponent);

        // (13) 广播 alpha_i 和 X'_i
        return {id, alpha_i, X_prime_i};
    }

    // 轮次 3: 仅计算并广播 Auth_i
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
        
        // (14) 计算 A_i
        const std::string& prev_id_for_R = participant_order[(my_idx + n - 1) % n];
        my_A_i = crypto.ScalarMultiply(received_R.at(prev_id_for_R), Integer(n) * r_i);
        for(size_t j=1; j < n; ++j) {
            const std::string& current_id = participant_order[(my_idx + j - 1) % n];
            Point term = crypto.ScalarMultiply(received_alpha.at(current_id), Integer(n - j));
            my_A_i = crypto.AddPoints(my_A_i, term);
        }

        // (15) 计算 beta_i
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
        
        // (16) 计算并准备广播密钥确认 Auth_i
        std::string auth_i_payload = ssid + PointToString(my_A_i) + PointToString(my_beta_i) + id;
        std::string auth_i = crypto.Hash(auth_i_payload);
        
        return {id, auth_i};
    }

    // 轮次 4: 验证所有 Auth 消息, 并在成功后最终确定会话密钥
    void round4_verify_auths_and_finalize(
        const std::map<std::string, Broadcast_Auth>& all_auths,
        const std::map<std::string, Broadcast_f>& all_f_messages,
        const std::vector<std::string>& participant_order
    ) {
        // 所有诚实的参与者最终都会计算出相同的 A 和 beta 值。
        // 因此，我们用自己计算出的 my_A_i 和 my_beta_i 来验证其他人广播的 auth_j。
        for(const auto& p : all_auths) {
            const std::string& other_id = p.first;
            const std::string& received_auth = p.second.auth_i;
            
            if (other_id == id) continue; // 跳过自己

            // 使用我的A和beta，但使用对方的ID来构建预期的哈希
            std::string expected_auth_payload = ssid + PointToString(my_A_i) + PointToString(my_beta_i) + other_id;
            std::string expected_auth = crypto.Hash(expected_auth_payload);

            if (expected_auth != received_auth) {
                throw std::runtime_error("Auth verification failed for participant " + other_id + "! Protocol aborted.");
            }
        }
        
        // (17) 所有验证通过后，计算最终会话密钥
        std::string sk_payload = sid;
        for(const auto& pid : participant_order) {
            sk_payload += all_f_messages.at(pid).f_i + PointToString(received_alpha.at(pid)) + PointToString(received_X_prime.at(pid));
        }
        sk_payload += PointToString(my_A_i) + PointToString(my_beta_i);
        session_key = crypto.Hash(sk_payload);
    }
};


// ------------------------------------------------------------------
//                      主函数 (数据大小分析版)
// ------------------------------------------------------------------
int main() {
    try {
        // --- 这一部分是您为每个 groupN.cpp 文件自定义的 ---
        #ifndef NUM_PARTICIPANTS
        #define NUM_PARTICIPANTS 4
        #endif
        std::string session_id = "SID_secure_IoT_2025";
        std::vector<std::string> p_order;
        for (int i = 1; i <= NUM_PARTICIPANTS; ++i) {
            p_order.push_back("P" + std::to_string(i));
        }
        // ---------------------------------------------------

        std::map<std::string, Participant> participants;
        for (const auto& id : p_order) {
            std::string password = "pass_" + id; 
            participants.emplace(std::piecewise_construct, 
                                 std::forward_as_tuple(id), 
                                 std::forward_as_tuple(id, password, session_id));
        }

        // === SETUP 阶段 ===
        std::map<std::string, PasswordFile> all_files;
        for (const auto& id : p_order) {
            participants.at(id).Setup();
            all_files[id] = participants.at(id).my_file;
        }

        // === 密钥交换 ===
        // --- 轮次 1 ---
        std::map<std::string, Broadcast_f> round1_messages;
        for (const auto& id : p_order) {
            round1_messages[id] = participants.at(id).round1_generate_f();
        }

        // --- 轮次 2 ---
        std::map<std::string, Broadcast_Alpha_X> round2_messages;
        for (size_t i = 0; i < NUM_PARTICIPANTS; ++i) {
            const auto& current_id = p_order[i];
            const auto& prev_id = p_order[(i + NUM_PARTICIPANTS - 1) % NUM_PARTICIPANTS];
            const auto& next_id = p_order[(i + 1) % NUM_PARTICIPANTS];
            round2_messages[current_id] = participants.at(current_id).round2_generate_alpha_X(
                round1_messages.at(prev_id), round1_messages.at(next_id), all_files
            );
        }

        // --- 轮次 3 & 4 ---
        std::vector<Broadcast_Alpha_X> r2_msg_vec;
        for(const auto& id : p_order) r2_msg_vec.push_back(round2_messages.at(id));
        std::map<std::string, Broadcast_Auth> round3_messages;
        for (const auto& id : p_order) {
            round3_messages[id] = participants.at(id).round3_compute_auth(r2_msg_vec, p_order);
        }
        for (const auto& id : p_order) {
             participants.at(id).round4_verify_auths_and_finalize(round3_messages, round1_messages, p_order);
        }

        // === 数据大小分析 ===
        const auto& p1_file = participants.at("P1").my_file;
        size_t file_size = p1_file.id.size() +
                           p1_file.X_i.x.ByteCount() + p1_file.X_i.y.ByteCount() +
                           p1_file.Y_i.x.ByteCount() + p1_file.Y_i.y.ByteCount() +
                           p1_file.x_hat_i.ByteCount() +
                           p1_file.hpw_i.size();
        
        size_t r1_broadcast_size = round1_messages.at("P1").f_i.size();
        
        const auto& r2_msg = round2_messages.at("P1");
        size_t r2_broadcast_size = r2_msg.alpha_i.x.ByteCount() + r2_msg.alpha_i.y.ByteCount() +
                                   r2_msg.X_prime_i.x.ByteCount() + r2_msg.X_prime_i.y.ByteCount();
        
        size_t r3_broadcast_size = round3_messages.at("P1").auth_i.size();

        // --- 只打印脚本需要的数据 ---
        std::cout << "Stored FILE[sid] size: " << file_size << " bytes\n";
        std::cout << "Round 1 broadcast size: " << r1_broadcast_size << " bytes\n";
        std::cout << "Round 2 broadcast size: " << r2_broadcast_size << " bytes\n";
        std::cout << "Round 3 broadcast size: " << r3_broadcast_size << " bytes\n";

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ Exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard Exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}


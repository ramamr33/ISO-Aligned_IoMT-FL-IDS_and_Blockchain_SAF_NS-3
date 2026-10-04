#include "ns3/inet-socket-address.h"
#include "ns3/socket.h"
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/netanim-module.h"
#include "ns3/log.h"
#include "ns3/energy-module.h"
#include "ns3/basic-energy-source.h"
#include "ns3/basic-energy-source-helper.h"
#include "ns3/wifi-radio-energy-model-helper.h"
#include <iostream>
#include <vector>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>
#include <map>
#include <numeric>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <unordered_map>
#include <regex>
#include <tuple>
#include <set>
#include <queue>
#include <functional>
#include <algorithm>
#include <cmath>

using namespace ns3;
using namespace ns3::energy;

NS_LOG_COMPONENT_DEFINE("IoMT_WIP_MITM_BFLIDS_Only");

std::ofstream energyLogFile;

// Comment out or set to 0 to minimize runtime console/file IO
#define VERBOSE_OUTPUT 0
#define VERBOSE_FILE_IO 0

std::map<uint32_t, std::vector<double>> flowArrivalTimes;

static const double EPS = 1e-9;

// QoS threat-level type used by the (inert) QoS buffers. In this BFLIDS-only build it is
// never set from any severity index, so every buffer stays at NONE.
enum SeverityLevel { NONE, LOW, MEDIUM, HIGH, CRITICAL_SEV };
const char* SeverityLabelStr[] = { "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

// ========== Utility Functions ==========

std::string base64_encode(const std::vector<unsigned char>& data) {
    BIO* bio, *b64;
    BUF_MEM* bufferPtr = nullptr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bio);

    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, data.data(), data.size());
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(b64);
    return result;
}

void displayDigitalSignature(const std::vector<unsigned char>& signature) {
#if VERBOSE_OUTPUT
    std::string base64_signature = base64_encode(signature);
    std::cout << "Digital Signature (Base64): " << base64_signature << std::endl;
#endif
}

void displayHexadecimal(const std::vector<unsigned char>& signature) {
#if VERBOSE_OUTPUT
    std::stringstream ss;
    for (unsigned char byte : signature) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)byte;
    }
    std::cout << "Digital Signature (Hex): " << ss.str() << std::endl;
#endif
}

uint32_t GetNodeFromContext(const std::string& context) {
    std::regex nodeRegex(R"(/NodeList/(\d+)/)");
    std::smatch match;
    if (std::regex_search(context, match, nodeRegex)) {
        return std::stoi(match[1].str());
    }
    return 0;
}

uint32_t GetAppFromContext(const std::string& context) {
    std::regex appRegex(R"(/ApplicationList/(\d+)/)");
    std::smatch match;
    if (std::regex_search(context, match, appRegex)) {
        return std::stoi(match[1].str());
    }
    return 0;
}

// ========== QoS Buffer Base Class ==========
class QoSBuffer {
public:
    struct BufferedItem {
        Ptr<Packet> packet;
        Address dest;
        Ptr<Socket> socket;
        double scheduledTime;
        uint32_t seqNum;
        double enqueueTime;
    };
    
protected:
    std::queue<BufferedItem> queue;
    double m_adaptiveBaseDelay;
    double m_adaptiveJitterBound;
    double m_lastSendTime = 0.0;
    double m_minGap = 0.001;
    std::function<void(uint32_t, double, double)> m_onPacketSent;

public:
    QoSBuffer(double baseDelay, double jitterBound) 
        : m_adaptiveBaseDelay(baseDelay), m_adaptiveJitterBound(jitterBound) {}
    
    virtual ~QoSBuffer() = default;
    
    void SetOnPacketSentCallback(std::function<void(uint32_t, double, double)> callback) {
        m_onPacketSent = callback;
    }
    
    virtual void Enqueue(const BufferedItem& item) {
        double now = Simulator::Now().GetSeconds();
        double jitter = ((double)rand() / RAND_MAX - 0.5) * 2 * m_adaptiveJitterBound;
        double sendAt = now + m_adaptiveBaseDelay + jitter;
        
        if (sendAt < m_lastSendTime + m_minGap) {
            sendAt = m_lastSendTime + m_minGap;
        }
        
        m_lastSendTime = sendAt;
        
        BufferedItem scheduled = item;
        scheduled.scheduledTime = sendAt;
        scheduled.enqueueTime = now;
        
        queue.push(scheduled);
        Simulator::Schedule(Seconds(sendAt - now), [this]() { this->Dequeue(); });
    }
    
    virtual void Dequeue() {
        if (queue.empty()) return;
        
        BufferedItem item = queue.front();
        queue.pop();
        
        double actualTime = Simulator::Now().GetSeconds();
        
        if (item.socket && item.dest != Address()) {
            item.socket->SendTo(item.packet, 0, item.dest);
        }
        
        if (m_onPacketSent) {
            m_onPacketSent(item.seqNum, item.scheduledTime, actualTime);
        }
    }
};

// ========== QoS Optimization Configuration ==========
struct QoSOptimizationConfig {
    std::map<SeverityLevel, double> severityJitterMultiplier = {
        {NONE, 1.0}, {LOW, 0.6}, {MEDIUM, 0.3}, {HIGH, 0.1}
    };
    std::map<uint32_t, double> minGapOverrides = {
        {1, 0.0005}, {2, 0.0005}, {3, 0.0007}, {4, 0.0007}, {5, 0.001}
    };
    std::map<uint32_t, size_t> maxBurstSize = {
        {1, 40}, {2, 40}, {3, 25}, {4, 25}, {5, 15},
        {6, 20}, {7, 20}, {8, 20}, {9, 20}
    };
};

// Forward declarations
class OptimizedQoSBuffer;
class Blockchain;

// ========== Blockchain and Security Classes ==========

class KeyPair {
public:
    KeyPair();
    bool IsEmpty() const;
    void Generate();
    std::string ToString() const;
private:
    std::string m_publicKey, m_privateKey;
};

KeyPair::KeyPair() : m_publicKey(""), m_privateKey("") {}
bool KeyPair::IsEmpty() const { return m_publicKey.empty() && m_privateKey.empty(); }
void KeyPair::Generate() { m_publicKey = "publicKey123"; m_privateKey = "privateKey123"; }
std::string KeyPair::ToString() const { return "PublicKey: " + m_publicKey + ", PrivateKey: " + m_privateKey; }

class Block {
public:
    static EVP_PKEY* s_keyPair;
    std::string previousHash;
    std::string timestamp;
    std::string data;
    std::string hash;
    std::vector<unsigned char> digitalSignature;

    Block(std::string prevHash, const std::string& data)
        : previousHash(std::move(prevHash)), data(encryptData(data)) {
        timestamp = std::to_string(time(0));
        hash = generateHash();
        digitalSignature = generateDigitalSignature(hash);
    }

    std::string GetHash() const { return hash; }
    std::string GetPreviousHash() const { return previousHash; }
    std::string GetData() const { return data; }
    std::string GetDigitalSignature() const {
        return base64_encode(digitalSignature);
    }

    void SetData(const std::string& newData) {
        data = encryptData(newData);
    }

    void SetDigitalSignature(const std::string& sigStr) {
        digitalSignature.clear();
    }

    std::string CalculateHash() const {
        std::string toHash = previousHash + timestamp + data;
        unsigned char hashBytes[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return "";
        
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, toHash.c_str(), toHash.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, hashBytes, &hashLen) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
        EVP_MD_CTX_free(ctx);
        
        std::stringstream ss;
        for (unsigned int i = 0; i < hashLen; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
        }
        return ss.str();
    }

    void RecalculateHash() {
        hash = generateHash();
        digitalSignature = generateDigitalSignature(hash);
    }

    std::string generateHash() {
        std::string toHash = previousHash + timestamp + data;
        unsigned char hashBytes[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return "";
        
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, toHash.c_str(), toHash.size()) != 1 ||
            EVP_DigestFinal_ex(ctx, hashBytes, &hashLen) != 1) {
            EVP_MD_CTX_free(ctx);
            return "";
        }
        EVP_MD_CTX_free(ctx);
        
        std::stringstream ss;
        for (unsigned int i = 0; i < hashLen; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
        }
        return ss.str();
    }

    std::string encryptData(const std::string& data) {
        return "Encrypted(" + data + ")";
    }

    EVP_PKEY* GetOrCreateKey() {
        if (!s_keyPair) {
            EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
                EVP_PKEY_keygen(ctx, &s_keyPair) <= 0) {
                if (ctx) EVP_PKEY_CTX_free(ctx);
                return nullptr;
            }
            EVP_PKEY_CTX_free(ctx);
        }
        return s_keyPair;
    }

    std::vector<unsigned char> generateDigitalSignature(const std::string& hash) {
        EVP_PKEY* pkey = GetOrCreateKey();
        std::vector<unsigned char> sig;
        if (!pkey) return sig;
        
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return sig;
        
        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_MD_CTX_free(ctx); 
            return sig;
        }
        if (EVP_DigestSignUpdate(ctx, hash.c_str(), hash.size()) != 1) {
            EVP_MD_CTX_free(ctx); 
            return sig;
        }
        
        size_t sigLen = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) != 1) {
            EVP_MD_CTX_free(ctx); 
            return sig;
        }
        
        sig.resize(sigLen);
        if (EVP_DigestSignFinal(ctx, sig.data(), &sigLen) != 1) {
            EVP_MD_CTX_free(ctx); 
            sig.clear(); 
            return sig;
        }
        
        sig.resize(sigLen);
        EVP_MD_CTX_free(ctx);
        return sig;
    }
};

EVP_PKEY* Block::s_keyPair = nullptr;

class Blockchain {
public:
    uint32_t nodeId;
    std::vector<Block> chain;

    Blockchain() : nodeId(0) { 
        chain.emplace_back("0", "Genesis Block"); 
    }
    
    Blockchain(uint32_t id) : nodeId(id) { 
        chain.emplace_back("0", "Genesis Block"); 
    }

    void addBlock(const std::string& data) {
        std::string prevHash = chain.back().GetHash();
        chain.emplace_back(prevHash, data);
    }

    void AddBlock(const std::string& data, const std::string& timestamp) {
        std::string prevHash = chain.back().GetHash();
        Block newBlock(prevHash, data);
        newBlock.timestamp = timestamp;
        newBlock.RecalculateHash();
        chain.push_back(newBlock);
    }

    void TamperLastBlock() {
        if (chain.size() > 1) {
            chain.back().SetData("Tampered Data - MALICIOUS!");
            chain.back().SetDigitalSignature("");
            chain.back().RecalculateHash();
        }
    }

    bool VerifyChain() const {
        for (size_t i = 1; i < chain.size(); ++i) {
            if (chain[i].GetPreviousHash() != chain[i-1].GetHash())
                return false;
            if (chain[i].GetHash() != chain[i].CalculateHash())
                return false;
        }
        return true;
    }

    void ExportChainToCsv(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Could not open file " << filename << " for writing" << std::endl;
            return;
        }
        
        file << "PreviousHash,Data,Timestamp,Hash,DigitalSignature\n";
        for (const auto& block : chain) {
            file << block.previousHash << ","
                 << "\"" << block.data << "\"" << ","
                 << block.timestamp << ","
                 << block.hash << ","
                 << "\"" << block.GetDigitalSignature() << "\"\n";
        }
        file.close();
        std::cout << "Blockchain exported to " << filename << std::endl;
    }

    std::vector<std::string> GetChainHashes() const {
        std::vector<std::string> hashes;
        hashes.reserve(chain.size());
        for (const auto& block : chain) {
            hashes.push_back(block.hash);
        }
        return hashes;
    }

    void replaceChain(const std::vector<Block>& newChain) {
        if (newChain.size() > chain.size() && VerifyNewChain(newChain)) {
            chain = newChain;
            std::cout << "Blockchain replaced with longer valid chain" << std::endl;
        } else {
            std::cout << "Chain replacement rejected: invalid or not longer" << std::endl;
        }
    }

    const std::vector<Block>& getChain() const { 
        return chain; 
    }

    void printChain() const {
        std::cout << "\n========== Blockchain for Node " << nodeId << " ==========" << std::endl;
        for (size_t i = 0; i < chain.size(); i++) {
            std::cout << "Block " << i << ":" << std::endl;
            std::cout << "  Previous Hash: " << chain[i].previousHash << std::endl;
            std::cout << "  Timestamp: " << chain[i].timestamp << std::endl;
            std::cout << "  Data: " << chain[i].data << std::endl;
            std::cout << "  Hash: " << chain[i].hash << std::endl;
            std::cout << "  Digital Signature: " << chain[i].GetDigitalSignature() << std::endl;
            std::cout << "  Valid: " << (chain[i].GetHash() == chain[i].CalculateHash() ? "Yes" : "No") << std::endl;
            std::cout << std::endl;
        }
        std::cout << "Chain Valid: " << (VerifyChain() ? "Yes" : "No") << std::endl;
        std::cout << "===============================================" << std::endl;
    }

private:
    bool VerifyNewChain(const std::vector<Block>& newChain) const {
        if (newChain.empty()) return false;
        
        for (size_t i = 1; i < newChain.size(); ++i) {
            if (newChain[i].previousHash != newChain[i-1].hash)
                return false;
            if (newChain[i].hash != newChain[i].CalculateHash())
                return false;
        }
        return true;
    }
};

// ========== Secure Communication ==========
class SecureCommunication {
public:
    SecureCommunication() {
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
    }

    std::vector<unsigned char> encryptAES(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, std::vector<unsigned char>& iv) {
        if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");
        iv.resize(16);
        RAND_bytes(iv.data(), 16);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0, finalLen = 0;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("EVP_EncryptInit_ex failed");

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) != 1)
            throw std::runtime_error("EVP_EncryptUpdate failed");

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outLen, &finalLen) != 1)
            throw std::runtime_error("EVP_EncryptFinal_ex failed");

        ciphertext.resize(outLen + finalLen);
        EVP_CIPHER_CTX_free(ctx);
        return ciphertext;
    }

    std::vector<unsigned char> decryptAES(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv) {
        if (key.size() != 32) throw std::runtime_error("Key must be 32 bytes for AES-256");
        if (iv.size() != 16) throw std::runtime_error("IV must be 16 bytes for AES-256-CBC");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) throw std::runtime_error("Failed to create cipher context");

        std::vector<unsigned char> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        int outlen = 0, tmplen = 0;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
            throw std::runtime_error("EVP_DecryptInit_ex failed");

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) != 1)
            throw std::runtime_error("EVP_DecryptUpdate failed");

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &tmplen) != 1)
            throw std::runtime_error("EVP_DecryptFinal_ex failed");

        plaintext.resize(outlen + tmplen);
        EVP_CIPHER_CTX_free(ctx);
        return plaintext;
    }

    void sendSecureData(const ns3::NodeContainer& nodes, const std::string& data){
        std::cout << "Pretend sending securely: " << data << std::endl;
    }

    void receiveSecureData(const std::string& encryptedData) {
        std::cout << "Pretend received securely: " << encryptedData << std::endl;
    }
};

// ========== Bluetooth Energy Model ==========
class BluetoothEnergyModel : public DeviceEnergyModel
{
public:
    enum State { IDLE, TRANSMITTING, RECEIVING };

    static TypeId GetTypeId(void) {
        static TypeId tid = TypeId("BluetoothEnergyModel")
            .SetParent<DeviceEnergyModel>()
            .SetGroupName("Energy")
            .AddConstructor<BluetoothEnergyModel>();
        return tid;
    }

    BluetoothEnergyModel()
        : m_txCurrentA(0.015), m_rxCurrentA(0.010), m_idleCurrentA(0.001), m_voltage(3.0),
          m_currentState(IDLE), m_totalEnergyConsumption(0.0), m_energySource(nullptr),
          m_lastUpdate(Seconds(0.0)), m_node(nullptr)
    {}

    void SetEnergySource(Ptr<EnergySource> source) override { m_energySource = source; }
    void SetTxCurrent(double val) { m_txCurrentA = val; }
    void SetRxCurrent(double val) { m_rxCurrentA = val; }
    void SetIdleCurrent(double val) { m_idleCurrentA = val; }
    void SetNode(Ptr<Node> node) { m_node = node; }

    void ChangeState(int newState) override final {
        State state = IDLE;
        if (newState == TRANSMITTING) state = TRANSMITTING;
        else if (newState == RECEIVING) state = RECEIVING;
        else state = IDLE;
        ChangeState(state);
    }

    void ChangeState(State newState) {
        UpdateEnergyConsumption();
        m_currentState = newState;
    }

    double GetTotalEnergyConsumption() const override { return m_totalEnergyConsumption; }

    void UpdateEnergyConsumption() 
    {
       Time now = Simulator::Now();
       Time duration = now - m_lastUpdate;
       double current = 0.0;
       switch (m_currentState) 
       {
           case IDLE: current = m_idleCurrentA; break;
           case TRANSMITTING: current = m_txCurrentA; break;
           case RECEIVING: current = m_rxCurrentA; break;
           default: current = 0.0; break;
       }
       
       double energyUsed = current * m_voltage * duration.GetSeconds();
       m_totalEnergyConsumption += energyUsed;
       m_lastUpdate = now;

       std::ofstream log("bluetooth_energy_log_wip.csv", std::ios::app);
       log << "time,node_id,state,total_energy\n";
       log << now.GetSeconds() << "," << (m_node ? m_node->GetId() : -1) << "," << m_currentState << "," << m_totalEnergyConsumption << std::endl;
       log.close();

       double totalEnergyKwh = m_totalEnergyConsumption / 3600000.0;
       std::cout << "[BluetoothEnergy] time: " << now.GetSeconds() << " s, node: " << (m_node ? m_node->GetId() : -1) << ", state: " << m_currentState << ", total_energy: " << totalEnergyKwh << " kWh" << std::endl; 
    }

    void HandleEnergyDepletion() override {
        NS_LOG_INFO("BluetoothEnergyModel: Energy depleted on node " << (m_node ? m_node->GetId() : 0));
    }
    void HandleEnergyRecharged() override {
        NS_LOG_INFO("BluetoothEnergyModel: Energy recharged on node " << (m_node ? m_node->GetId() : 0));
    }
    void HandleEnergyChanged() override {
        NS_LOG_INFO("BluetoothEnergyModel: Energy changed on node " << (m_node ? m_node->GetId() : 0));
    }
    void DoDispose() override {
        m_energySource = nullptr;
        m_node = nullptr;
        DeviceEnergyModel::DoDispose();
    }
private:
    double m_txCurrentA, m_rxCurrentA, m_idleCurrentA, m_voltage;
    State m_currentState;
    double m_totalEnergyConsumption;
    Ptr<EnergySource> m_energySource;
    Time m_lastUpdate;
    Ptr<Node> m_node;
};

// ========== WIP Application ==========
struct InfusionCommand {
  std::string drugName;
  double dose;
  double rate;
  std::string route;
};

class WipApplication : public ns3::Application {
public:
  WipApplication() {}
  virtual ~WipApplication() {}

  void Setup(Ptr<Socket> socket, Address address) {
    m_socket = socket;
    m_peer = address;
  }

  void SetDrugProtocol(const InfusionCommand& protocol) {
    m_protocol = protocol;
  }

  virtual void StartApplication() override {
    m_socket->Bind();
    m_socket->SetRecvCallback(MakeCallback(&WipApplication::HandleRead, this));
  }

  void HandleRead(Ptr<Socket> socket) {
    Ptr<Packet> packet;
    Address from;
    while ((packet = socket->RecvFrom(from))) {
      std::ostringstream msg;
      msg << packet->ToString();

      InfusionCommand cmd = {/*drugName=*/"Fentanyl", /*dose=*/100, /*rate=*/10, /*route=*/"IV"};

      if (cmd.dose > m_protocol.dose) {
        NS_LOG_UNCOND("WIP ALERT: Dose exceeds safe limits!");
      } else {
        NS_LOG_UNCOND("WIP INFO: Infusion accepted.");
      }
    }
  }

private:
  Ptr<Socket> m_socket;
  Address m_peer;
  InfusionCommand m_protocol;
};

// =====================================================================================
//  BFLIDS re-implementation module (Begum et al., Sensors 2024, 24(14):4591)
//  ------------------------------------------------------------------------------------
//  Pure C++17, no external ML library, so it compiles inside NS-3 like the original
//  LocalModel. Implements, as described in Sec. 3.3-3.4 of Begum et al.:
//    * Adaptive-Max-Pooling CNN: 2 conv layers, 3 fully-connected layers, 1 dropout
//      layer (their Fig. 3), adapted here to a single sigmoid output (binary
//      attack/normal) instead of their 15-class softmax.
//    * KL-divergence-based adaptive FedAvg (their Eqs. 2-6, Algorithm 1).
//    * SMOTE minority oversampling before local training (their Sec. 4.1).
//  Hyperparameters NOT specified by Begum et al. are exposed in BflidsConfig and
//  must be reported as re-implementation assumptions in the manuscript.
// =====================================================================================
#include <vector>
#include <array>
#include <random>
#include <cmath>
#include <algorithm>
#include <numeric>

namespace bflids {

// ---------------- Configuration (unspecified-in-paper values marked ASSUMED) ----------
struct BflidsConfig {
    int    numFeatures   = 12;    // per-window flow features (see FeatureVector below)
    int    conv1Filters  = 16;    // ASSUMED
    int    conv2Filters  = 32;    // ASSUMED
    int    kernel        = 3;     // ASSUMED (padding 'same')
    int    adaptivePool  = 2;     // ASSUMED adaptive max-pool output length
    int    fc1Units      = 64;    // ASSUMED
    int    fc2Units      = 32;    // ASSUMED
    double dropout       = 0.2;   // ASSUMED (after FC1, per their Fig. 3)
    double learningRate  = 1e-3;  // ASSUMED (Adam)
    int    batchSize     = 32;    // ASSUMED
    int    localEpochs   = 20;    // Begum et al. Sec. 4.2
    double klLambda      = 1.0;   // ASSUMED (lambda in Eqs. 3 and 6)
    double serverLR      = 1.0;   // ASSUMED (eta in Eq. 5; 1.0 = plain replacement)
    bool   useSmote      = true;  // Begum et al. Sec. 4.1
    int    smoteK        = 5;     // standard SMOTE default
    uint32_t seed        = 2024;
};

// ---------------- CNN model --------------------------------------------------------
class CnnModel {
public:
    BflidsConfig cfg;
    int F, C1, C2, K, P1len, AP, flatLen;   // derived sizes
    // Parameters (flattened row-major)
    std::vector<double> w1, b1, w2, b2, wf1, bf1, wf2, bf2, wf3, bf3;

    explicit CnnModel(const BflidsConfig& c = BflidsConfig()) : cfg(c) {
        F = cfg.numFeatures; C1 = cfg.conv1Filters; C2 = cfg.conv2Filters; K = cfg.kernel;
        P1len = F / 2; AP = cfg.adaptivePool; flatLen = C2 * AP;
        std::mt19937 g(cfg.seed);
        auto he = [&](std::vector<double>& v, size_t n, int fanIn) {
            std::normal_distribution<double> d(0.0, std::sqrt(2.0 / fanIn));
            v.resize(n); for (auto& x : v) x = d(g);
        };
        he(w1, (size_t)C1 * 1 * K, 1 * K);              b1.assign(C1, 0.0);
        he(w2, (size_t)C2 * C1 * K, C1 * K);             b2.assign(C2, 0.0);
        he(wf1, (size_t)cfg.fc1Units * flatLen, flatLen); bf1.assign(cfg.fc1Units, 0.0);
        he(wf2, (size_t)cfg.fc2Units * cfg.fc1Units, cfg.fc1Units); bf2.assign(cfg.fc2Units, 0.0);
        he(wf3, (size_t)cfg.fc2Units, cfg.fc2Units);     bf3.assign(1, 0.0);
    }

    std::vector<std::vector<double>*> Params() {
        return {&w1,&b1,&w2,&b2,&wf1,&bf1,&wf2,&bf2,&wf3,&bf3};
    }
    std::vector<double> GetParameters() {
        std::vector<double> out;
        for (auto* p : Params()) out.insert(out.end(), p->begin(), p->end());
        return out;
    }
    void SetParameters(const std::vector<double>& v) {
        size_t o = 0;
        for (auto* p : Params()) { for (auto& x : *p) x = v[o++]; }
    }

    // Activation cache for backprop
    struct Cache {
        std::vector<double> x, z1, a1, p1; std::vector<int> p1idx;
        std::vector<double> z2, a2, ap; std::vector<int> apidx;
        std::vector<double> h1, d1mask, h1d, h2, out; // fc
        double logit = 0, prob = 0;
    };

    static double Sigmoid(double z) { return 1.0 / (1.0 + std::exp(-z)); }

    // Adaptive max pool bin boundaries (PyTorch convention)
    static void Bin(int i, int inLen, int outLen, int& s, int& e) {
        s = (int)std::floor((double)i * inLen / outLen);
        e = (int)std::ceil((double)(i + 1) * inLen / outLen);
    }

    double Forward(const std::vector<double>& x, Cache& c, bool train, std::mt19937* rng) const {
        c.x = x;
        int pad = K / 2;
        // Conv1: 1 -> C1, length F
        c.z1.assign((size_t)C1 * F, 0.0);
        for (int o = 0; o < C1; ++o) for (int t = 0; t < F; ++t) {
            double s = b1[o];
            for (int k = 0; k < K; ++k) { int ti = t + k - pad; if (ti >= 0 && ti < F) s += w1[o*K + k] * x[ti]; }
            c.z1[o*F + t] = s;
        }
        c.a1.resize(c.z1.size());
        for (size_t i = 0; i < c.z1.size(); ++i) c.a1[i] = std::max(0.0, c.z1[i]);
        // MaxPool k=2 s=2 -> length P1len
        c.p1.assign((size_t)C1 * P1len, 0.0); c.p1idx.assign((size_t)C1 * P1len, 0);
        for (int o = 0; o < C1; ++o) for (int t = 0; t < P1len; ++t) {
            int i0 = o*F + 2*t, i1 = i0 + 1;
            bool first = c.a1[i0] >= c.a1[i1];
            c.p1[o*P1len + t] = first ? c.a1[i0] : c.a1[i1];
            c.p1idx[o*P1len + t] = first ? i0 : i1;
        }
        // Conv2: C1 -> C2, length P1len
        int L = P1len;
        c.z2.assign((size_t)C2 * L, 0.0);
        for (int o = 0; o < C2; ++o) for (int t = 0; t < L; ++t) {
            double s = b2[o];
            for (int ci = 0; ci < C1; ++ci) for (int k = 0; k < K; ++k) {
                int ti = t + k - pad; if (ti >= 0 && ti < L) s += w2[(o*C1 + ci)*K + k] * c.p1[ci*L + ti];
            }
            c.z2[o*L + t] = s;
        }
        c.a2.resize(c.z2.size());
        for (size_t i = 0; i < c.z2.size(); ++i) c.a2[i] = std::max(0.0, c.z2[i]);
        // Adaptive max pool -> AP
        c.ap.assign((size_t)flatLen, 0.0); c.apidx.assign((size_t)flatLen, 0);
        for (int o = 0; o < C2; ++o) for (int b = 0; b < AP; ++b) {
            int s, e; Bin(b, L, AP, s, e);
            int best = o*L + s;
            for (int t = s; t < e; ++t) if (c.a2[o*L + t] > c.a2[best]) best = o*L + t;
            c.ap[o*AP + b] = c.a2[best]; c.apidx[o*AP + b] = best;
        }
        // FC1 + ReLU + Dropout
        int U1 = cfg.fc1Units, U2 = cfg.fc2Units;
        c.h1.assign(U1, 0.0); c.d1mask.assign(U1, 1.0); c.h1d.assign(U1, 0.0);
        for (int u = 0; u < U1; ++u) {
            double s = bf1[u];
            for (int i = 0; i < flatLen; ++i) s += wf1[u*flatLen + i] * c.ap[i];
            c.h1[u] = std::max(0.0, s);
        }
        if (train && cfg.dropout > 0 && rng) {
            std::bernoulli_distribution keep(1.0 - cfg.dropout);
            for (int u = 0; u < U1; ++u) c.d1mask[u] = keep(*rng) ? 1.0 / (1.0 - cfg.dropout) : 0.0;
        }
        for (int u = 0; u < U1; ++u) c.h1d[u] = c.h1[u] * c.d1mask[u];
        // FC2 + ReLU
        c.h2.assign(U2, 0.0);
        for (int u = 0; u < U2; ++u) {
            double s = bf2[u];
            for (int i = 0; i < U1; ++i) s += wf2[u*U1 + i] * c.h1d[i];
            c.h2[u] = std::max(0.0, s);
        }
        // FC3 -> logit
        double s = bf3[0];
        for (int i = 0; i < U2; ++i) s += wf3[i] * c.h2[i];
        c.logit = s; c.prob = Sigmoid(s);
        return c.prob;
    }

    double Predict(const std::vector<double>& x) const { Cache c; return Forward(x, c, false, nullptr); }

    // Accumulate gradients of BCE loss for one sample into g (same layout as Params()).
    void Backward(const Cache& c, double y, std::vector<std::vector<double>>& g) const {
        int pad = K / 2, L = P1len, U1 = cfg.fc1Units, U2 = cfg.fc2Units;
        double dlogit = c.prob - y;
        // FC3
        std::vector<double> dh2(U2, 0.0);
        for (int i = 0; i < U2; ++i) { g[8][i] += dlogit * c.h2[i]; dh2[i] = dlogit * wf3[i]; }
        g[9][0] += dlogit;
        // FC2 (ReLU)
        std::vector<double> dh1d(U1, 0.0);
        for (int u = 0; u < U2; ++u) {
            double dz = (c.h2[u] > 0) ? dh2[u] : 0.0;
            if (dz == 0.0) continue;
            g[7][u] += dz;
            for (int i = 0; i < U1; ++i) { g[6][u*U1 + i] += dz * c.h1d[i]; dh1d[i] += dz * wf2[u*U1 + i]; }
        }
        // Dropout + FC1 (ReLU)
        std::vector<double> dap(flatLen, 0.0);
        for (int u = 0; u < U1; ++u) {
            double dz = (c.h1[u] > 0) ? dh1d[u] * c.d1mask[u] : 0.0;
            if (dz == 0.0) continue;
            g[5][u] += dz;
            for (int i = 0; i < flatLen; ++i) { g[4][u*flatLen + i] += dz * c.ap[i]; dap[i] += dz * wf1[u*flatLen + i]; }
        }
        // Adaptive max pool -> a2
        std::vector<double> dz2((size_t)C2 * L, 0.0);
        for (int i = 0; i < flatLen; ++i) {
            int idx = c.apidx[i];
            if (c.z2[idx] > 0) dz2[idx] += dap[i];   // ReLU gate
        }
        // Conv2
        std::vector<double> dp1((size_t)C1 * L, 0.0);
        for (int o = 0; o < C2; ++o) for (int t = 0; t < L; ++t) {
            double d = dz2[o*L + t]; if (d == 0.0) continue;
            g[3][o] += d;
            for (int ci = 0; ci < C1; ++ci) for (int k = 0; k < K; ++k) {
                int ti = t + k - pad; if (ti < 0 || ti >= L) continue;
                g[2][(o*C1 + ci)*K + k] += d * c.p1[ci*L + ti];
                dp1[ci*L + ti] += d * w2[(o*C1 + ci)*K + k];
            }
        }
        // MaxPool -> a1 -> ReLU
        std::vector<double> dz1((size_t)C1 * F, 0.0);
        for (size_t i = 0; i < dp1.size(); ++i) {
            int idx = c.p1idx[i];
            if (c.z1[idx] > 0) dz1[idx] += dp1[i];
        }
        // Conv1
        for (int o = 0; o < C1; ++o) for (int t = 0; t < F; ++t) {
            double d = dz1[o*F + t]; if (d == 0.0) continue;
            g[1][o] += d;
            for (int k = 0; k < K; ++k) { int ti = t + k - pad; if (ti >= 0 && ti < F) g[0][o*K + k] += d * c.x[ti]; }
        }
    }

    static double Bce(double p, double y) {
        const double e = 1e-9; p = std::min(std::max(p, e), 1.0 - e);
        return -(y * std::log(p) + (1.0 - y) * std::log(1.0 - p));
    }

    // Local training with Adam (state reset each FL round, as is common in FL).
    // Returns mean training loss of the final epoch.
    double Train(const std::vector<std::vector<double>>& X, const std::vector<double>& Y,
                 int epochs, double lr, std::mt19937& rng) {
        if (X.empty()) return 0.0;
        auto P = Params();
        std::vector<std::vector<double>> m, v;
        for (auto* p : P) { m.emplace_back(p->size(), 0.0); v.emplace_back(p->size(), 0.0); }
        const double b1a = 0.9, b2a = 0.999, eps = 1e-8; int step = 0;
        std::vector<size_t> idx(X.size()); std::iota(idx.begin(), idx.end(), 0);
        double lastLoss = 0.0;
        for (int ep = 0; ep < epochs; ++ep) {
            std::shuffle(idx.begin(), idx.end(), rng);
            double epLoss = 0.0;
            for (size_t s = 0; s < idx.size(); s += cfg.batchSize) {
                size_t e = std::min(idx.size(), s + (size_t)cfg.batchSize);
                std::vector<std::vector<double>> g;
                for (auto* p : P) g.emplace_back(p->size(), 0.0);
                for (size_t j = s; j < e; ++j) {
                    Cache c; Forward(X[idx[j]], c, true, &rng);
                    epLoss += Bce(c.prob, Y[idx[j]]);
                    Backward(c, Y[idx[j]], g);
                }
                double n = double(e - s); ++step;
                for (size_t pi = 0; pi < P.size(); ++pi) for (size_t k = 0; k < P[pi]->size(); ++k) {
                    double gr = g[pi][k] / n;
                    m[pi][k] = b1a * m[pi][k] + (1 - b1a) * gr;
                    v[pi][k] = b2a * v[pi][k] + (1 - b2a) * gr * gr;
                    double mh = m[pi][k] / (1 - std::pow(b1a, step));
                    double vh = v[pi][k] / (1 - std::pow(b2a, step));
                    (*P[pi])[k] -= lr * mh / (std::sqrt(vh) + eps);
                }
            }
            lastLoss = epLoss / X.size();
        }
        return lastLoss;
    }
};

// ---------------- SMOTE (binary, minority class) --------------------------------------
inline void Smote(std::vector<std::vector<double>>& X, std::vector<double>& Y, int k, std::mt19937& rng) {
    std::vector<size_t> pos, neg;
    for (size_t i = 0; i < Y.size(); ++i) (Y[i] > 0.5 ? pos : neg).push_back(i);
    if (pos.empty() || neg.empty()) return;            // nothing to balance against
    auto& minority = (pos.size() < neg.size()) ? pos : neg;
    auto& majority = (pos.size() < neg.size()) ? neg : pos;
    double minLabel = Y[minority[0]];
    size_t need = majority.size() - minority.size();
    if (need == 0) return;
    std::vector<size_t> minIdx = minority;  // snapshot
    std::uniform_int_distribution<size_t> pick(0, minIdx.size() - 1);
    std::uniform_real_distribution<double> gap(0.0, 1.0);
    for (size_t n = 0; n < need; ++n) {
        const auto& a = X[minIdx[pick(rng)]];
        // k nearest minority neighbours of a
        std::vector<std::pair<double,size_t>> d;
        for (size_t j : minIdx) {
            double s = 0; for (size_t f = 0; f < a.size(); ++f) { double t = a[f] - X[j][f]; s += t*t; }
            d.push_back({s, j});
        }
        std::sort(d.begin(), d.end());
        size_t kk = std::min<size_t>(k, d.size() > 1 ? d.size() - 1 : 0);
        std::vector<double> syn = a;
        if (kk > 0) {
            std::uniform_int_distribution<size_t> nb(1, kk);
            const auto& b = X[d[nb(rng)].second];
            double lam = gap(rng);
            for (size_t f = 0; f < a.size(); ++f) syn[f] = a[f] + lam * (b[f] - a[f]);
        }
        X.push_back(syn); Y.push_back(minLabel);
    }
}

// ---------------- KL-divergence adaptive FedAvg (Eqs. 2-6) ----------------------------
// Interpretation (ASSUMED; Begum et al. do not define P_i / P_t operationally):
//   P_i = client i's empirical label distribution  [p(attack), p(normal)]
//   P_t = global model's mean predicted distribution on client i's data.
inline double KlBinary(double p, double q) {
    const double e = 1e-3;
    p = std::min(std::max(p, e), 1.0 - e); q = std::min(std::max(q, e), 1.0 - e);
    return p * std::log(p / q) + (1 - p) * std::log((1 - p) / (1 - q));
}

struct ClientData {
    std::vector<std::vector<double>> X;
    std::vector<double> Y;
};

class BflidsCoordinator {
public:
    BflidsConfig cfg;
    CnnModel global;
    int round = 0;
    double lastLoss = 0.0;
    std::vector<double> lastAlpha, lastKL;
    std::mt19937 rng;

    explicit BflidsCoordinator(const BflidsConfig& c) : cfg(c), global(c), rng(c.seed + 7) {}

    // One synchronous round of Algorithm 1 (all clients participate; client sampling
    // proportional to alpha, line 14 of Algorithm 1, is omitted because only a
    // handful of clients exist in this topology -- reported as an assumption).
    double RunRound(std::vector<CnnModel>& clients, const std::vector<ClientData*>& data) {
        std::vector<double> gW = global.GetParameters();
        std::vector<double> agg(gW.size(), 0.0);
        double alphaSum = 0.0, lossSum = 0.0; int trained = 0;
        lastAlpha.assign(clients.size(), 0.0); lastKL.assign(clients.size(), 0.0);

        for (size_t i = 0; i < clients.size(); ++i) {
            clients[i].SetParameters(gW);                      // start from global model
            ClientData& d = *data[i];
            if (d.X.empty()) continue;                         // no data -> no update
            // Eq. 2: divergence between client data and global model distribution
            double pi = std::accumulate(d.Y.begin(), d.Y.end(), 0.0) / d.Y.size();
            double pt = 0.0; for (auto& x : d.X) pt += global.Predict(x); pt /= d.X.size();
            double kl = KlBinary(pi, pt);
            double alpha = 1.0 / (1.0 + cfg.klLambda * kl);   // Eq. 3
            double lrI = cfg.learningRate * alpha;             // Eq. 6
            // Local training (with SMOTE, Sec. 4.1)
            auto X = d.X; auto Y = d.Y;
            if (cfg.useSmote) Smote(X, Y, cfg.smoteK, rng);
            lossSum += clients[i].Train(X, Y, cfg.localEpochs, lrI, rng); ++trained;
            auto w = clients[i].GetParameters();
            for (size_t k = 0; k < agg.size(); ++k) agg[k] += alpha * w[k];   // Eq. 4 numerator
            alphaSum += alpha; lastAlpha[i] = alpha; lastKL[i] = kl;
        }
        if (alphaSum > 0) {
            for (size_t k = 0; k < agg.size(); ++k) {
                double wAvg = agg[k] / alphaSum;                       // Eq. 4
                gW[k] = gW[k] + cfg.serverLR * (wAvg - gW[k]);         // Eq. 5 (delta form)
            }
            global.SetParameters(gW);
        }
        for (auto& c : clients) c.SetParameters(gW);                 // broadcast
        ++round;
        lastLoss = trained ? lossSum / trained : lastLoss;
        return lastLoss;
    }
};

} // namespace bflids


// ========== NodeMonitor (flow ownership + retransmission buffer only) ==========
struct NodeMonitor {
    std::map<uint32_t, Ptr<Packet>> lostPacketsBuffer;
    std::string deviceType;
    NodeMonitor(const std::string& d = "") : deviceType(d) {}
};

// ========== OptimizedQoSBuffer with Chapter 6 Integration ==========
class OptimizedQoSBuffer : public QoSBuffer {
private:
    QoSOptimizationConfig config;
    SeverityLevel currentThreatLevel = NONE;
    uint32_t flowId;
    std::queue<double> recentJitters;
    static constexpr size_t JITTER_HISTORY_SIZE = 50;
    double m_adaptiveBaseDelay = 0.8, m_adaptiveJitterBound = 0.6;
    
public:
    OptimizedQoSBuffer(uint32_t fId, double baseDelay, double jitterBound) 
        : QoSBuffer(baseDelay, jitterBound), flowId(fId) {
        
        m_adaptiveBaseDelay = baseDelay;
        m_adaptiveJitterBound = jitterBound;
        
        if (config.minGapOverrides.count(flowId)) {
            m_minGap = config.minGapOverrides[flowId];
        }
    }
    
    void UpdateThreatLevel(SeverityLevel level) {
        if (currentThreatLevel != level) {
            currentThreatLevel = level;
            AdaptParameters();
        }
    }
    
    void AdaptParameters() {
        double multiplier = config.severityJitterMultiplier[currentThreatLevel];
        m_adaptiveJitterBound = m_adaptiveBaseDelay * multiplier;
        
        if ((flowId <= 5) && (currentThreatLevel >= MEDIUM)) {
            m_adaptiveBaseDelay = m_adaptiveBaseDelay * 0.8;
        }
        
        std::cout << "[QoS Adapt] Flow " << flowId 
                  << " threat=" << SeverityLabelStr[currentThreatLevel]
                  << " newJitter=" << m_adaptiveJitterBound
                  << " newDelay=" << m_adaptiveBaseDelay << std::endl;
    }
    
    void AdaptiveFeedbackTuning() {
        if (recentJitters.empty()) return;

        std::queue<double> temp = recentJitters;
        double sum = 0.0;
        while (!temp.empty()) {
            sum += temp.front();
            temp.pop();
        }
        
        double avgJitter = sum / recentJitters.size();

        if (avgJitter > 0.0005) {
            m_adaptiveJitterBound *= 0.8;
            m_adaptiveBaseDelay *= 0.9;
        } else if (avgJitter < 0.0001) {
            m_adaptiveJitterBound *= 1.2;
            m_adaptiveBaseDelay *= 1.1;
        }

        m_adaptiveJitterBound = std::max(0.00005, std::min(m_adaptiveJitterBound, 0.02));
        m_adaptiveBaseDelay = std::max(0.001, std::min(m_adaptiveBaseDelay, 0.05));

        std::cout << "[AdaptiveFeedback] Flow " << flowId
                  << " avgJitter=" << avgJitter
                  << " newJitterBound=" << m_adaptiveJitterBound
                  << " newBaseDelay=" << m_adaptiveBaseDelay << std::endl;
    }
    
    void EnhancedEnqueue(const BufferedItem& item) {
        double now = Simulator::Now().GetSeconds();
    
    // Calculate adaptive jitter
        double jitter = ((double)rand() / RAND_MAX - 0.5) * 2 * m_adaptiveJitterBound;
        
        // Apply jitter smoothing for critical flows
        if (flowId <= 5) {
            jitter = SmoothJitter(jitter);
        }
        
        double sendAt = now + m_adaptiveBaseDelay + jitter;
        
        // Ensure minimum gap with burst handling
        if (sendAt < m_lastSendTime + m_minGap) {
            sendAt = m_lastSendTime + m_minGap;
        }
        
        // Update tracking
        m_lastSendTime = sendAt;
        TrackJitter(fabs(jitter));
        
        BufferedItem scheduled = item;
        scheduled.scheduledTime = sendAt;
        scheduled.enqueueTime = now;
        
        // Check burst limits
        if (queue.size() < config.maxBurstSize[flowId]) {
            queue.push(scheduled);
            Simulator::Schedule(Seconds(sendAt - now), [this]() { this->Dequeue(); });
        } else {
            // Drop or defer based on flow criticality
            if (flowId <= 2) { // Critical flows - force through
                queue.push(scheduled);
                Simulator::Schedule(Seconds(sendAt - now), [this]() { this->Dequeue(); });
            } else {
                std::cout << "[QoS] Flow " << flowId << " burst limit reached, packet deferred" << std::endl;
            }
        }
    }
    
private:
    double SmoothJitter(double rawJitter) {
        static std::map<uint32_t, double> smoothedJitter;
        const double alpha = 0.3;
        
        if (smoothedJitter.count(flowId) == 0) {
            smoothedJitter[flowId] = rawJitter;
        } else {
            smoothedJitter[flowId] = alpha * rawJitter + (1 - alpha) * smoothedJitter[flowId];
        }
        
        return smoothedJitter[flowId];
    }
    
    void TrackJitter(double jitter) {
        recentJitters.push(jitter);
        if (recentJitters.size() > JITTER_HISTORY_SIZE) {
            recentJitters.pop();
        }
    }
};

// ========== Global Variables ==========
std::unordered_map<uint32_t, NodeMonitor*> flowToMonitor;
std::map<std::pair<uint32_t, uint32_t>, uint32_t> nodeAppToFlowId;
std::map<uint32_t, std::vector<Ptr<Packet>>> flowLostPacketsBuffer;
std::vector<SecureCommunication> nodeSecurity;
std::vector<std::vector<unsigned char>> nodeKeys;
NodeContainer wifiApNode, wifiNodes, mitmNode, hexoskinNodes;
std::vector<NodeMonitor>* g_nodeMonitors = nullptr;
std::vector<NodeMonitor>* g_nodeMonitors2 = nullptr;
Blockchain* g_blockchain = nullptr;

std::map<uint32_t, std::unique_ptr<QoSBuffer>> flowQoSBuffers;
std::map<uint32_t, std::vector<double>> flowJitterHistory;

struct BufferedPacket {
    Ptr<Packet> packet;
    Address dest;
    Ptr<Socket> socket;
    Time sendTime;
    uint32_t seqNum;
};

std::map<uint32_t, std::vector<BufferedPacket>> flowBufferedPackets;
std::map<std::pair<uint32_t, uint32_t>, Ptr<Socket>> nodeAppSocketMap;
std::map<std::pair<uint32_t, uint32_t>, Address> nodeAppDestMap;
std::map<uint32_t, std::map<uint32_t, BufferedPacket>> sentPacketBuffer;
std::map<uint32_t, std::set<uint32_t>> receivedPacketUids;

bool mitmActive = true;

// Local-training hyperparameters for the real FL rounds
static const int   kLocalEpochsPerRound = 5;

// FL Model info — now backed by a real trained per-node LocalModel + multi-round FedAvg
// =====================================================================================
// ========== BFLIDS-ONLY BUILD (Begum et al., Sensors 2024) ==========================
// =====================================================================================
// Same IoMT network, traffic, MITM attacker on the WIP (/NodeList/0 MacRx) and seeds as
// the FL-IDS simulation, but intrusion detection and mitigation are performed ONLY by
// the BFLIDS re-implementation (adaptive-max-pooling CNN + KL-divergence adaptive FedAvg
// + SMOTE). No wASI, no FL-IDS logistic/FedAvg classifier and no multi-standard mapping
// exist in this build.
//   --mitigate=1 : BFLIDS disables the attacker when its global model flags any flow
//   --mitigate=0 : detection only (attacker stays active) -> clean detection metrics
// Every flow/window is logged with the BFLIDS score (prequential evaluation: each window
// is scored by the global model trained only on EARLIER windows).
// =====================================================================================

std::string g_attackType      = "mitm";
bool        g_mitigate        = true;
double      g_rearmDelay      = 0.0;     // 0 = never re-arm
double      g_attackStart     = 0.0;     // 0 = attack active from t=0 (original behaviour)
double      g_sampleInterval  = 1.0;
double      g_roundInterval   = 10.0;
double      g_detectThreshold = 0.5;
std::string g_labelMode       = "global";   // global | targeted
std::string g_partition       = "owner";    // owner | all
uint32_t    g_seed            = 1;
bool        g_windowAttackSeen = false;
uint32_t    g_mitigationEvents = 0;
double      g_firstMitigationTime = -1.0;

Ipv4Address g_wipAddress;
Ptr<Ipv4FlowClassifier> g_flowClassifier;
std::set<uint32_t> g_targetedFlows;
std::map<uint32_t, ns3::FlowMonitor::FlowStats> g_prevStats;
std::map<uint32_t, uint32_t> g_flowOwner;
std::map<uint32_t, std::vector<double>> g_lastBflidsFeatures;
std::ofstream g_detLog, g_roundLog;

bflids::BflidsConfig g_bcfg;
bflids::BflidsCoordinator* g_bflids = nullptr;
std::vector<bflids::CnnModel> g_bClients;
std::vector<bflids::ClientData> g_bData;
static const size_t kBflidsBufferCap = 2000;

void RetransmitPackets(uint32_t flowId, uint32_t nodeIdx);

void EnableAttacker() {
    if (g_attackType != "mitm") return;
    if (!mitmActive) {
        mitmActive = true;
        g_windowAttackSeen = true;
        std::cout << "[BFLIDS-only] MITM (re)armed at t=" << Simulator::Now().GetSeconds() << "s" << std::endl;
        if (g_roundLog.is_open())
            g_roundLog << Simulator::Now().GetSeconds() << ",attacker,0,,,ARMED,1\n";
    }
}

void DisableAttacker(const std::string& source) {
    if (!mitmActive) return;
    mitmActive = false;
    g_mitigationEvents++;
    if (g_firstMitigationTime < 0) g_firstMitigationTime = Simulator::Now().GetSeconds();
    std::cout << "MITM DISABLED for recovery! (decision by " << source << " at t="
              << Simulator::Now().GetSeconds() << "s)" << std::endl;
    if (g_roundLog.is_open())
        g_roundLog << Simulator::Now().GetSeconds() << "," << source << ",0,,,MITIGATED,0\n";
    if (g_rearmDelay > 0.0)
        Simulator::Schedule(Seconds(g_rearmDelay), &EnableAttacker);
}

void RefreshFlowMaps(const std::map<uint32_t, ns3::FlowMonitor::FlowStats>& stats, uint32_t numClients) {
    uint32_t idx = 0;
    for (const auto& kv : stats) {
        if (!g_flowOwner.count(kv.first)) g_flowOwner[kv.first] = idx % numClients;
        idx++;
        if (g_flowClassifier) {
            Ipv4FlowClassifier::FiveTuple t = g_flowClassifier->FindFlow(kv.first);
            if (t.destinationAddress == g_wipAddress) g_targetedFlows.insert(kv.first);
        }
    }
}

bool FlowLabel(uint32_t flowId, bool attackState) {
    if (!attackState) return false;
    if (g_labelMode == "targeted") return g_targetedFlows.count(flowId) > 0;
    return true;
}

// 12 per-window flow features (log-scaled, clipped to [0,1]) -- raw traffic statistics
// only, in the spirit of BFLIDS' raw network-traffic features; no severity index.
std::vector<double> BflidsFeatures(double tx, double rx, double lost, double txB, double rxB,
                                   double tputKbps, double delayMs, double jitterMs, double fwdPerRx) {
    auto L = [](double v, double cap) { return std::min(1.0, std::log1p(std::max(0.0, v)) / std::log1p(cap)); };
    auto C = [](double v) { return std::min(1.0, std::max(0.0, v)); };
    double lossR = tx > 0 ? lost / tx : 0.0;
    double delivR = tx > 0 ? rx / tx : 0.0;
    double txSize = tx > 0 ? txB / tx : 0.0;
    double rxSize = rx > 0 ? rxB / rx : 0.0;
    return { L(tx, 5000), L(rx, 5000), L(lost, 5000), C(lossR), C(delivR),
             L(tputKbps, 5000), L(delayMs, 1000), L(jitterMs, 1000),
             C(txSize / 1500.0), C(rxSize / 1500.0), L(txB, 5e6), C(fwdPerRx / 5.0) };
}

void BflidsRound();

void BflidsSampleTick(Ptr<FlowMonitor> monitor, uint32_t numClients, double stopTime) {
    double now = Simulator::Now().GetSeconds();
    monitor->CheckForLostPackets();
    auto stats = monitor->GetFlowStats();
    RefreshFlowMaps(stats, numClients);
    bool attackLabelState = g_windowAttackSeen;

    for (const auto& kv : stats) {
        uint32_t fid = kv.first;
        const auto& cur = kv.second;
        ns3::FlowMonitor::FlowStats prev{};
        if (g_prevStats.count(fid)) prev = g_prevStats[fid];
        auto D = [](uint64_t a, uint64_t b) { return a > b ? double(a - b) : 0.0; };
        double tx   = D(cur.txPackets, prev.txPackets);
        double rx   = D(cur.rxPackets, prev.rxPackets);
        double lost = D(cur.lostPackets, prev.lostPackets);
        double txB  = D(cur.txBytes, prev.txBytes);
        double rxB  = D(cur.rxBytes, prev.rxBytes);
        double dly  = (cur.delaySum - prev.delaySum).GetSeconds();
        double jit  = (cur.jitterSum - prev.jitterSum).GetSeconds();
        double fwd  = D(cur.timesForwarded, prev.timesForwarded);
        if (tx == 0 && rx == 0 && lost == 0) continue;          // idle flow in this window

        double tputKbps = rxB * 8.0 / 1000.0 / g_sampleInterval;
        double meanDelay = rx > 0 ? dly / rx : 0.0;
        double meanJitter = rx > 1 ? jit / (rx - 1) : 0.0;
        double lossPct = tx > 0 ? 100.0 * lost / tx : 0.0;
        bool labelGlobal = attackLabelState;
        bool labelTargeted = attackLabelState && g_targetedFlows.count(fid);
        bool label = FlowLabel(fid, attackLabelState);

        auto x = BflidsFeatures(tx, rx, lost, txB, rxB, tputKbps, meanDelay * 1000.0,
                                meanJitter * 1000.0, rx > 0 ? fwd / rx : 0.0);
        g_lastBflidsFeatures[fid] = x;
        double bProb = g_bflids ? g_bflids->global.Predict(x) : 0.0;   // model from earlier rounds

        uint32_t owner = g_flowOwner.count(fid) ? g_flowOwner[fid] : 0;
        bflids::ClientData* targets[16]; size_t nt = 0;
        if (g_partition == "all") { for (auto& d : g_bData) targets[nt++] = &d; }
        else targets[nt++] = &g_bData[owner];
        for (size_t i = 0; i < nt; ++i) {
            targets[i]->X.push_back(x); targets[i]->Y.push_back(label ? 1.0 : 0.0);
            if (targets[i]->X.size() > kBflidsBufferCap) {
                targets[i]->X.erase(targets[i]->X.begin()); targets[i]->Y.erase(targets[i]->Y.begin());
            }
        }

        if (g_detLog.is_open()) {
            Ipv4FlowClassifier::FiveTuple t{};
            if (g_flowClassifier) t = g_flowClassifier->FindFlow(fid);
            g_detLog << "bflids," << g_seed << "," << std::fixed << std::setprecision(3) << now << ","
                     << fid << "," << t.sourceAddress << ":" << t.sourcePort << ","
                     << t.destinationAddress << ":" << t.destinationPort << ","
                     << owner << "," << ((owner <= 4) ? "WIP" : "SHS") << ","
                     << labelGlobal << "," << labelTargeted << ","
                     << std::setprecision(0) << tx << "," << rx << "," << lost << ","
                     << std::setprecision(6) << tputKbps << "," << meanDelay << "," << meanJitter << ","
                     << lossPct << "," << (g_bflids ? g_bflids->round : 0) << "," << bProb << ","
                     << mitmActive << "\n";
        }
        g_prevStats[fid] = cur;
    }
    double r = std::fmod(now + 1e-6, g_roundInterval);
    if (r < g_sampleInterval * 0.5) BflidsRound();
    // Set AFTER the BFLIDS decision, so a mitigation at this instant correctly marks the
    // next window as attack-free (otherwise one window per mitigation would be mislabelled).
    g_windowAttackSeen = mitmActive;

    if (now + g_sampleInterval <= stopTime + 1e-9)
        Simulator::Schedule(Seconds(g_sampleInterval), &BflidsSampleTick, monitor, numClients, stopTime);
}

void BflidsRound() {
    if (!g_bflids) return;
    std::vector<bflids::ClientData*> dp;
    for (auto& d : g_bData) dp.push_back(&d);
    double loss = g_bflids->RunRound(g_bClients, dp);

    bool detected = false; uint32_t nFlag = 0;
    for (const auto& kv : g_lastBflidsFeatures) {
        if (g_bflids->global.Predict(kv.second) >= g_detectThreshold) { detected = true; nFlag++; }
    }
    std::cout << "[BFLIDS] Round " << g_bflids->round << " | mean local loss=" << std::fixed
              << std::setprecision(4) << loss << " | flows flagged=" << nFlag << " | alpha=";
    for (double a : g_bflids->lastAlpha) std::cout << std::setprecision(3) << a << " ";
    std::cout << std::endl;
    if (g_roundLog.is_open())
        g_roundLog << Simulator::Now().GetSeconds() << ",bflids," << g_bflids->round << ","
                   << loss << "," << nFlag << "," << (detected ? "DETECT" : "clear") << "," << mitmActive << "\n";
    if (g_mitigate && detected) {
        DisableAttacker("bflids");
        for (const auto& [flowId, monitorPtr] : flowToMonitor)
            Simulator::ScheduleNow(&RetransmitPackets, flowId, 0u);
    }
}

// ========== Helper Functions ==========

void AssociateFlowsToMonitors(const std::map<uint32_t, ns3::FlowMonitor::FlowStats>& stats, 
                              std::vector<NodeMonitor>& nodeMonitors) {
    uint32_t monitorIndex = 0;
    for (const auto& flowStat : stats) {
        if (monitorIndex < nodeMonitors.size()) {
            flowToMonitor[flowStat.first] = &nodeMonitors[monitorIndex % nodeMonitors.size()];
            monitorIndex++;
        }
    }
}

void MITMNodeRxCallback(Ptr<const Packet> packet) {
    if (!mitmActive) {
        Ptr<Node> mitmNodePtr = mitmNode.Get(0);
        Ptr<NetDevice> mitmDevice = mitmNodePtr->GetDevice(0);
        mitmDevice->Send(packet->Copy(), mitmDevice->GetAddress(), 0);
        std::cout << "MITM BYPASSED (disabled, forwarding packet UID " << packet->GetUid() << ")" << std::endl;
        return;
    }
    
    std::cout << "MITM Node received a packet of size " << packet->GetSize() << " bytes" << std::endl;
    const size_t maxPacketSize = 512;
    
    if (!packet || packet->GetSize() == 0) {
        std::cerr << "Error: Received invalid packet!" << std::endl;
        return;
    }
    
    if (packet->GetSize() > maxPacketSize) {
        std::cout << "MITM Node dropping a large packet." << std::endl;
        if (g_blockchain) g_blockchain->addBlock("MITM dropped packet of size " + std::to_string(packet->GetSize()));
        return;
    }
    
    if (mitmNode.GetN() == 0) {
        std::cerr << "MITM node container is empty!" << std::endl;
        return;
    }
    
    Ptr<Node> mitmNodePtr = mitmNode.Get(0);
    if (!mitmNodePtr) {
        std::cerr << "MITM node pointer is null!" << std::endl;
        return;
    }
    
    Ptr<NetDevice> mitmDevice = mitmNodePtr->GetDevice(0);
    if (!mitmDevice) {
        std::cerr << "MITM device is not initialized!" << std::endl;
        return;
    }
    
    std::vector<uint8_t> data(packet->GetSize());
    packet->CopyData(data.data(), packet->GetSize());
    data[0] = 0xAB;
    Ptr<Packet> modifiedPacket = Create<Packet>(data.data(), data.size());
    mitmDevice->Send(modifiedPacket, mitmDevice->GetAddress(), 0);
    
    std::cout << "MITM Node successfully modified and forwarded the packet." << std::endl;
    if (g_blockchain) g_blockchain->addBlock("MITM modified and forwarded packet UID " + std::to_string(packet->GetUid()));
}

void RemainingEnergyCallback(uint32_t nodeId, double oldVal, double newVal) {
    double now = ns3::Simulator::Now().GetSeconds();
    double oldValKwh = oldVal / 3600000.0;
    double newValKwh = newVal / 3600000.0;
    energyLogFile << now << ',' << nodeId << ',' << oldValKwh << ',' << newValKwh << '\n';
    
    std::cout << std::fixed << std::setprecision(8);
    if (nodeId == 100) {
        std::cout << "[Hexoskin] remaining energy: " << oldValKwh << " kWh --> " << newValKwh << " kWh" << std::endl;
    } else {
        std::cout << "Node " << nodeId << " remaining energy: " << oldValKwh << " kWh --> " << newValKwh << " kWh" << std::endl;
    }
}

void OnOffTxTrace(std::string context, Ptr<const Packet> packet) {
#if VERBOSE_OUTPUT
    uint32_t nodeIdx = GetNodeFromContext(context);
    uint32_t appIdx = GetAppFromContext(context);
    auto it = nodeAppToFlowId.find({nodeIdx, appIdx});
    if (it != nodeAppToFlowId.end()) {
        uint32_t flowId = it->second;
        auto sockIt = nodeAppSocketMap.find({nodeIdx, appIdx});
        Ptr<Socket> sock = (sockIt != nodeAppSocketMap.end()) ? sockIt->second : nullptr;
        auto destIt = nodeAppDestMap.find({nodeIdx, appIdx});
        Address dest = (destIt != nodeAppDestMap.end()) ? destIt->second : Address();
        uint32_t seqNum = packet->GetUid();

        std::vector<unsigned char> plainData(packet->GetSize());
        packet->CopyData(plainData.data(), packet->GetSize());
        std::vector<unsigned char> iv;
        auto encryptedData = nodeSecurity[nodeIdx].encryptAES(plainData, nodeKeys[nodeIdx], iv);

        std::vector<unsigned char> fullPacket = iv;
        fullPacket.insert(fullPacket.end(), encryptedData.begin(), encryptedData.end());
        Ptr<Packet> securePacket = Create<Packet>(fullPacket.data(), fullPacket.size());

        sentPacketBuffer[flowId][seqNum] = {securePacket->Copy(), dest, sock, Simulator::Now(), seqNum};

        if (flowQoSBuffers.count(flowId)) {
            QoSBuffer::BufferedItem item = {
                securePacket->Copy(), dest, sock, 0.0, seqNum, 0.0
            };
            flowQoSBuffers[flowId]->Enqueue(item);
        } else {
            if (sock && dest != Address()) {
                sock->SendTo(securePacket->Copy(), 0, dest);
            }
        }
    }
#endif
}

void TrackOnOffSocketsAndDest(Ptr<Application> app, uint32_t nodeIdx, uint32_t appIdx, Address dest) {
    Ptr<OnOffApplication> onoff = DynamicCast<OnOffApplication>(app);
    if (onoff) {
        Ptr<Socket> sock = onoff->GetSocket();
        if (sock) {
            nodeAppSocketMap[{nodeIdx, appIdx}] = sock;
            nodeAppDestMap[{nodeIdx, appIdx}] = dest;
        }
    }
}

void RetransmitPackets(uint32_t flowId, uint32_t nodeIdx) {
    std::cout << "[Retransmit] Called for flowId: " << flowId << ", nodeIdx: " << nodeIdx << std::endl;
    auto &sent = sentPacketBuffer[flowId];
    auto &received = receivedPacketUids[flowId];
    uint32_t retransmitCount = 0;
    
    for (const auto& [uid, bp] : sent) {
        if (received.find(uid) == received.end()) {
            std::cout << "[Retransmit] Flow " << flowId << " Node " << nodeIdx
                      << " Retransmitting packet UID " << uid << std::endl;
            
            if (!bp.socket) {
                std::cout << "[Retransmit] ERROR: Null socket for Flow " << flowId << std::endl;
                continue;
            }
            if (bp.dest == Address()) {
                std::cout << "[Retransmit] ERROR: Empty dest for Flow " << flowId << std::endl;
                continue;
            }
            
            bp.socket->SendTo(bp.packet->Copy(), 0, bp.dest);
            retransmitCount++;
        }
    }
    
    std::cout << "[Retransmit] Total retransmitted for flow " << flowId << ": " << retransmitCount << std::endl;
}

// DetectAndRecoverMITM now also consults each node's REAL trained local model
// (in addition to the legacy scalar-loss anomaly check) before triggering recovery.
// Periodic housekeeping kept at the original 10 s cadence (lost-packet accounting and
// per-round buffer cleanup) so network behaviour is identical to the FL-IDS simulation.
// All FL-IDS / wASI processing that used to run here is removed in this build.
void PeriodicHousekeeping(double interval, double stopTime, Ptr<FlowMonitor> monitor,
                          std::vector<NodeMonitor>& nodeMonitors, uint32_t numWifiNodes) {
    double now = Simulator::Now().GetSeconds();
    if (now + interval > stopTime) return;
    monitor->CheckForLostPackets();
    auto stats = monitor->GetFlowStats();
    AssociateFlowsToMonitors(stats, nodeMonitors);
    for (auto& pair : flowJitterHistory) pair.second.clear();

    Simulator::Schedule(Seconds(interval), &PeriodicHousekeeping, interval, stopTime,
                        monitor, std::ref(nodeMonitors), numWifiNodes);

    for (auto& pair : flowArrivalTimes) pair.second.clear();
    for (auto& pair : flowJitterHistory) pair.second.clear();
    for (auto& pair : receivedPacketUids) pair.second.clear();
    for (auto& pair : sentPacketBuffer) pair.second.clear();
    for (auto& pair : flowBufferedPackets) pair.second.clear();
    for (auto& pair : flowLostPacketsBuffer) pair.second.clear();
    for (auto& m : nodeMonitors) m.lostPacketsBuffer.clear();
}

void SinkRxTrace(std::string context, Ptr<const Packet> packet, const Address &address) {
    uint32_t nodeIdx = GetNodeFromContext(context);
    uint32_t appIdx = GetAppFromContext(context);
    uint32_t flowId = nodeAppToFlowId[{nodeIdx, appIdx}];

    std::set<uint32_t> encryptedFlows = {1,2,3,4,5};
    if (encryptedFlows.count(flowId) == 0) {
        return;
    }

    receivedPacketUids[flowId].insert(packet->GetUid());
    
    std::vector<unsigned char> buffer(packet->GetSize());
    packet->CopyData(buffer.data(), buffer.size());

    if (buffer.size() < 17 || buffer.size() > 256) {
        return;
    }
    
    if (buffer.size() < 16) {
        std::cerr << "[SinkRxTrace] ERROR: Packet too small to contain IV!" << std::endl;
        return;
    }
    
    std::vector<unsigned char> iv(buffer.begin(), buffer.begin() + 16);
    std::vector<unsigned char> encryptedData(buffer.begin() + 16, buffer.end());

    try {
        std::vector<unsigned char> decrypted = nodeSecurity[nodeIdx].decryptAES(encryptedData, nodeKeys[nodeIdx], iv);
        std::string plaintext(decrypted.begin(), decrypted.end());
    } catch (const std::exception& ex) {
        std::cerr << "[SinkRxTrace] Decryption failed: " << ex.what() << std::endl;
    }
}

void ScheduleTrackOnOffSocket(uint32_t nodeIdx, uint32_t appIdx, Ptr<Application> app, Address dest, double delay = 0.1) {
    Simulator::Schedule(Seconds(delay), [=]() {
        TrackOnOffSocketsAndDest(app, nodeIdx, appIdx, dest);
    });
}

void PrintSinkSockets(Ptr<Node> node, uint32_t nodeIdx) {
    std::cout << "Node " << nodeIdx << " Sockets after start:" << std::endl;
    for (uint32_t j = 0; j < node->GetNApplications(); ++j) {
        Ptr<Application> app = node->GetApplication(j);
        Ptr<PacketSink> sink = DynamicCast<PacketSink>(app);
        if (sink) {
            Ptr<Socket> listeningSocket = sink->GetListeningSocket();
            if (listeningSocket) {
                Address address;
                listeningSocket->GetSockName(address);
                InetSocketAddress inetAddr = InetSocketAddress::ConvertFrom(address);
                std::cout << "  AppIdx " << j << ": PacketSink, Listening Port: " << inetAddr.GetPort()
                          << " IP: " << inetAddr.GetIpv4() << std::endl;
            } else {
                std::cout << "  AppIdx " << j << ": PacketSink, Listening Socket NOT AVAILABLE (even after start)." << std::endl;
            }
        }
    }
}

void MacRxTrace(std::string context, Ptr<const Packet> packet) {
    // Minimal trace
}

void RxTimeTracer(Ptr<const Packet> packet) {
    double now = Simulator::Now().GetSeconds();
    uint32_t flowId = packet->GetUid();
    flowArrivalTimes[flowId].push_back(now);
}

void TxTrace(Ptr<const Packet> packet) {
    // Minimal trace
}

void SinkRxCallback(ns3::Ptr<const ns3::Packet> packet, const ns3::Address &from) {
    // Minimal callback
}

class NodeTracer {
public:
    NodeTracer(uint32_t nodeId) : m_nodeId(nodeId) {}
    void Tx(Ptr<const Packet> packet) {}
    void Rx(Ptr<const Packet> packet, const Address &address) {}
private:
    uint32_t m_nodeId;
};

void ScheduleAdaptiveFeedback(double interval, double stopTime) {
    double now = Simulator::Now().GetSeconds();
    if (now + interval > stopTime) return;

    for (auto& [flowId, bufferPtr] : flowQoSBuffers) {
        auto* optimizedBuffer = dynamic_cast<OptimizedQoSBuffer*>(bufferPtr.get());
        if (optimizedBuffer) {
            optimizedBuffer->AdaptiveFeedbackTuning();
        }
    }

    Simulator::Schedule(Seconds(interval), &ScheduleAdaptiveFeedback, interval, stopTime);
}

// ========== Main Simulation ==========

int main(int argc, char *argv[]) {
    double simulationTime = 60.0;
    uint32_t numWifiNodes = 9;
    std::string attackType = "mitm";
    uint32_t seedValue = 1;
    std::string flowOutputPath = "flowmonitor-stats_chapter6_integrated_wip.xml";

    CommandLine cmd;
    cmd.AddValue("attackType", "Type of attack: none / mitm", attackType);
    cmd.AddValue("seed", "Random seed for this run", seedValue);
    cmd.AddValue("outputFile", "Flow monitor output file", flowOutputPath);
    std::string detLogPath = "detection_windows.csv", roundLogPath = "fl_rounds.csv";
    cmd.AddValue("mitigate", "1 = BFLIDS disables the attacker on detection; 0 = detect only", g_mitigate);
    cmd.AddValue("rearmDelay", "Seconds after mitigation before attacker re-arms (0 = never)", g_rearmDelay);
    cmd.AddValue("attackStart", "Time (s) at which the MITM becomes active (0 = from start)", g_attackStart);
    cmd.AddValue("sampleInterval", "BFLIDS per-window sampling interval (s)", g_sampleInterval);
    cmd.AddValue("roundInterval", "BFLIDS federated round interval (s)", g_roundInterval);
    cmd.AddValue("labelMode", "Training/eval label: global (original) | targeted (WIP-bound flows only)", g_labelMode);
    cmd.AddValue("partition", "BFLIDS client data: owner (flow->one client) | all (every client sees all flows)", g_partition);
    cmd.AddValue("localEpochs", "BFLIDS local epochs per round", g_bcfg.localEpochs);
    cmd.AddValue("klLambda", "BFLIDS KL sensitivity lambda (Eqs. 3,6)", g_bcfg.klLambda);
    cmd.AddValue("serverLR", "BFLIDS server learning rate eta (Eq. 5)", g_bcfg.serverLR);
    cmd.AddValue("smote", "BFLIDS SMOTE oversampling (1/0)", g_bcfg.useSmote);
    cmd.AddValue("detLog", "Per-window detection log CSV", detLogPath);
    cmd.AddValue("roundLog", "Per-round FL/mitigation log CSV", roundLogPath);
    cmd.Parse(argc, argv);
    g_attackType = attackType;
    g_seed = seedValue;
    g_bcfg.seed = 2024 + seedValue;
    mitmActive = (attackType == "mitm" && g_attackStart <= 0.0);
    g_windowAttackSeen = mitmActive;
    g_detLog.open(detLogPath);
    g_detLog << "framework,seed,time,flow_id,src,dst,owner_client,owner_device,label_global,label_targeted,"
                "tx_pkts,rx_pkts,lost_pkts,throughput_kbps,mean_delay_s,mean_jitter_s,loss_pct,"
                "bflids_round,bflids_prob,mitm_active\n";
    g_roundLog.open(roundLogPath);
    g_roundLog << "time,framework,round,mean_loss,nodes_or_flows_flagged,decision,mitm_active\n";
    std::cout << "[BFLIDS-only] mitigate=" << g_mitigate
              << " attackType=" << attackType << " attackStart=" << g_attackStart
              << " rearmDelay=" << g_rearmDelay << " labelMode=" << g_labelMode
              << " partition=" << g_partition << std::endl;

    RngSeedManager::SetSeed(seedValue);

    SSL_library_init();
    SSL_load_error_strings();

    std::cout << "\n=== BFLIDS-only build (Begum et al., Sensors 2024) ===\n"
              << "Detection + mitigation: adaptive-max-pooling CNN, KL-divergence adaptive FedAvg, SMOTE.\n"
              << "No wASI, no FL-IDS FedAvg classifier, no multi-standard mapping.\n"
              << "================================================================\n\n";

    wifiNodes.Create(numWifiNodes);
    nodeSecurity.resize(wifiNodes.GetN());
    nodeKeys.resize(wifiNodes.GetN(), std::vector<unsigned char>(32));
    for (auto& key : nodeKeys) {
        RAND_bytes(key.data(), 32);
    }
    wifiApNode.Create(1);
    mitmNode.Create(1);
    hexoskinNodes.Create(1);

    // Network setup
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211n);
    wifi.SetRemoteStationManager("ns3::MinstrelHtWifiManager");
    WifiMacHelper mac;
    Ssid ssid = Ssid("IoMTNetwork");

    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
    NetDeviceContainer staDevices = wifi.Install(phy, mac, wifiNodes);

    mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
    NetDeviceContainer apDevice = wifi.Install(phy, mac, wifiApNode);

    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid));
    NetDeviceContainer mitmDevice = wifi.Install(phy, mac, mitmNode);

    InternetStackHelper stack;
    stack.Install(wifiNodes);
    stack.Install(wifiApNode);
    stack.Install(mitmNode);
    stack.Install(hexoskinNodes);

    Ipv4AddressHelper address;
    address.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer staInterfaces = address.Assign(staDevices);
    Ipv4InterfaceContainer apInterface = address.Assign(apDevice);
    Ipv4InterfaceContainer mitmInterface = address.Assign(mitmDevice);

    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
        "MinX", DoubleValue(0.0), "MinY", DoubleValue(0.0), 
        "DeltaX", DoubleValue(10.0), "DeltaY", DoubleValue(10.0),
        "GridWidth", UintegerValue(3), "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(wifiNodes);

    Ptr<ListPositionAllocator> apPosition = CreateObject<ListPositionAllocator>();
    apPosition->Add(Vector(0.0, 0.0, 0.0));
    mobility.SetPositionAllocator(apPosition);
    mobility.Install(wifiApNode);

    Ptr<ListPositionAllocator> mitmPosition = CreateObject<ListPositionAllocator>();
    mitmPosition->Add(Vector(15.0, 15.0, 0.0));
    mobility.SetPositionAllocator(mitmPosition);
    mobility.Install(mitmNode);

    mobility.Install(hexoskinNodes);

    // Bluetooth P2P Link
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("3Mbps"));
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));
    
    Ptr<UniformRandomVariable> jitter = CreateObject<UniformRandomVariable>();
    jitter->SetAttribute("Min", DoubleValue(0.0));
    jitter->SetAttribute("Max", DoubleValue(0.005));
    double jitterSeconds = jitter->GetValue();
    Time delay = Seconds(0.002 + jitterSeconds);
    p2p.SetChannelAttribute("Delay", TimeValue(delay));

    NetDeviceContainer p2pDevices = p2p.Install(wifiNodes.Get(1), hexoskinNodes.Get(0));

    Ptr<RateErrorModel> lossModel = CreateObject<RateErrorModel>();
    lossModel->SetAttribute("ErrorRate", DoubleValue(0.02));
    p2pDevices.Get(0)->SetAttribute("ReceiveErrorModel", PointerValue(lossModel));
    p2pDevices.Get(1)->SetAttribute("ReceiveErrorModel", PointerValue(lossModel));

    Ipv4AddressHelper p2pAddress;
    p2pAddress.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfaces = p2pAddress.Assign(p2pDevices);

    // Bluetooth sink app
    uint16_t bluetoothPort = 8070;
    Address bluetoothSinkAddress(InetSocketAddress(p2pInterfaces.GetAddress(1), bluetoothPort));
    PacketSinkHelper bluetoothSinkHelper("ns3::UdpSocketFactory", bluetoothSinkAddress);
    ApplicationContainer sinkApp = bluetoothSinkHelper.Install(wifiNodes.Get(1));
    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(60.0));

    OnOffHelper bluetoothTraffic("ns3::UdpSocketFactory", bluetoothSinkAddress);
    bluetoothTraffic.SetAttribute("DataRate", StringValue("2Kbps"));
    bluetoothTraffic.SetAttribute("PacketSize", UintegerValue(50));
    bluetoothTraffic.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    bluetoothTraffic.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer bluetoothApp = bluetoothTraffic.Install(hexoskinNodes.Get(0));
    bluetoothApp.Start(Seconds(1.0));
    bluetoothApp.Stop(Seconds(60.0));
    
    // Energy models
    BasicEnergySourceHelper energySourceHelper;
    energySourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(100.0));
    EnergySourceContainer sources = energySourceHelper.Install(wifiNodes);
    WifiRadioEnergyModelHelper wifiEnergyHelper;
    wifiEnergyHelper.Set("TxCurrentA", DoubleValue(0.380));
    wifiEnergyHelper.Set("RxCurrentA", DoubleValue(0.313));
    wifiEnergyHelper.Set("IdleCurrentA", DoubleValue(0.273));
    wifiEnergyHelper.Set("SleepCurrentA", DoubleValue(0.035));
    
    BasicEnergySourceHelper hexoskinEnergySourceHelper;
    hexoskinEnergySourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(50.0));
    EnergySourceContainer hexoskinSource = hexoskinEnergySourceHelper.Install(hexoskinNodes);

    Ptr<BasicEnergySource> hexoSrc = DynamicCast<BasicEnergySource>(hexoskinSource.Get(0));
    Ptr<BluetoothEnergyModel> btModel = CreateObject<BluetoothEnergyModel>();
    btModel->SetTxCurrent(0.15);
    btModel->SetRxCurrent(0.12);
    btModel->SetIdleCurrent(0.01);
    btModel->SetEnergySource(hexoSrc);
    btModel->SetNode(hexoskinNodes.Get(0));
    hexoSrc->AppendDeviceEnergyModel(btModel);

    btModel->ChangeState(BluetoothEnergyModel::TRANSMITTING);
    btModel->ChangeState(BluetoothEnergyModel::IDLE);

    for (uint32_t i = 0; i < wifiNodes.GetN(); ++i) {
        Ptr<BasicEnergySource> src = DynamicCast<BasicEnergySource>(sources.Get(i));
        if (src) {
            src->TraceConnectWithoutContext("RemainingEnergy", MakeBoundCallback(&RemainingEnergyCallback, i));
        }
    }

    if (hexoSrc) {
        uint32_t hexoskinId = hexoskinNodes.Get(0)->GetId();
        hexoSrc->TraceConnectWithoutContext("RemainingEnergy", MakeBoundCallback(&RemainingEnergyCallback, hexoskinId));
    }

    // Baxter Infusion Pump
    uint16_t baxterPort = 8080;
    Address baxterAddress(InetSocketAddress(staInterfaces.GetAddress(0), baxterPort));
    PacketSinkHelper baxterSink("ns3::UdpSocketFactory", baxterAddress);
    ApplicationContainer baxterApp = baxterSink.Install(wifiNodes.Get(0));
    baxterApp.Start(Seconds(1.0));
    baxterApp.Stop(Seconds(60.0));

    OnOffHelper baxterTraffic("ns3::UdpSocketFactory", baxterAddress);
    baxterTraffic.SetAttribute("DataRate", StringValue("1Mbps"));
    baxterTraffic.SetAttribute("PacketSize", UintegerValue(512));
    ApplicationContainer baxterTrafficApp = baxterTraffic.Install(wifiNodes.Get(1));
    baxterTrafficApp.Start(Seconds(2.0));
    baxterTrafficApp.Stop(Seconds(60.0));

    // Hexoskin smartphone
    uint16_t hexoskinPort = 8090;
    Address hexoskinAddress(InetSocketAddress(staInterfaces.GetAddress(1), hexoskinPort));
    PacketSinkHelper hexoskinSink("ns3::UdpSocketFactory", hexoskinAddress);
    ApplicationContainer hexoskinApp = hexoskinSink.Install(wifiNodes.Get(1));
    hexoskinApp.Start(Seconds(5.0));
    hexoskinApp.Stop(Seconds(60.0));

    OnOffHelper hexoskinTraffic("ns3::UdpSocketFactory", hexoskinAddress);
    hexoskinTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    hexoskinTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer hexoskinTrafficApp = hexoskinTraffic.Install(wifiNodes.Get(2));
    hexoskinTrafficApp.Start(Seconds(6.0));
    hexoskinTrafficApp.Stop(Seconds(60.0));
    
    // WIP Application
    Ptr<Socket> wipSocket = Socket::CreateSocket(wifiNodes.Get(0), UdpSocketFactory::GetTypeId());
    InetSocketAddress remoteAddr = InetSocketAddress(staInterfaces.GetAddress(0), 9);

    Ptr<WipApplication> wipApp = CreateObject<WipApplication>();
    InfusionCommand safeLimits = {"Fentanyl", 75.0, 10.0, "IV"};
    wipApp->SetDrugProtocol(safeLimits); 
    wipApp->Setup(wipSocket, remoteAddr);
    wifiNodes.Get(0)->AddApplication(wipApp);
    wipApp->SetStartTime(Seconds(1.0));
    wipApp->SetStopTime(Seconds(10.0));
    
    Ptr<Socket> cmdSocket = Socket::CreateSocket(wifiNodes.Get(1), UdpSocketFactory::GetTypeId());
    InetSocketAddress wipAddr = InetSocketAddress(staInterfaces.GetAddress(0), 9);
    cmdSocket->Connect(wipAddr);

    Simulator::Schedule(Seconds(2.0), [&]() {
        Ptr<Packet> packet = Create<Packet>((uint8_t*)"Fentanyl", 8);
        cmdSocket->Send(packet);
    });
    
    // Pulse Oximeter
    uint16_t oximeterPort = 8100;
    Address oximeterAddress(InetSocketAddress(staInterfaces.GetAddress(1), oximeterPort));
    PacketSinkHelper oximeterSink("ns3::UdpSocketFactory", oximeterAddress);
    ApplicationContainer oximeterApp = oximeterSink.Install(wifiNodes.Get(2));
    oximeterApp.Start(Seconds(1.0));
    oximeterApp.Stop(Seconds(60.0));
    
    OnOffHelper oximeterTraffic("ns3::UdpSocketFactory", oximeterAddress);
    oximeterTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    oximeterTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer oximeterTrafficApp = oximeterTraffic.Install(wifiNodes.Get(3));
    oximeterTrafficApp.Start(Seconds(2.0));
    oximeterTrafficApp.Stop(Seconds(60.0));
    
    // Blood Pressure Monitor
    uint16_t pressurePort = 8110;
    Address pressureAddress(InetSocketAddress(staInterfaces.GetAddress(2), pressurePort));
    PacketSinkHelper pressureSink("ns3::UdpSocketFactory", pressureAddress);
    ApplicationContainer pressureApp = pressureSink.Install(wifiNodes.Get(3));
    pressureApp.Start(Seconds(1.0));
    pressureApp.Stop(Seconds(60.0));
    
    OnOffHelper pressureTraffic("ns3::UdpSocketFactory", pressureAddress);
    pressureTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    pressureTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer pressureTrafficApp = pressureTraffic.Install(wifiNodes.Get(4));
    pressureTrafficApp.Start(Seconds(2.0));
    pressureTrafficApp.Stop(Seconds(60.0));
    
    // EMR Server
    uint16_t serverPort = 8120;
    Address serverAddress(InetSocketAddress(staInterfaces.GetAddress(4), serverPort));
    PacketSinkHelper serverSink("ns3::UdpSocketFactory", serverAddress);
    ApplicationContainer serverApp = serverSink.Install(wifiNodes.Get(4));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(60.0));

    OnOffHelper serverTraffic("ns3::UdpSocketFactory", serverAddress);
    serverTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    serverTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer serverTrafficApp = serverTraffic.Install(wifiNodes.Get(5));
    serverTrafficApp.Start(Seconds(2.0));
    serverTrafficApp.Stop(Seconds(60.0));

    // MQTT Broker
    uint16_t mqttPort = 8883;
    Ipv4Address mqttIpAddress = staInterfaces.GetAddress(5);
    Address mqttSocketAddress = InetSocketAddress(mqttIpAddress, mqttPort);
    PacketSinkHelper mqttSink("ns3::UdpSocketFactory", mqttSocketAddress);
    ApplicationContainer mqttApp = mqttSink.Install(wifiNodes.Get(5));
    mqttApp.Start(Seconds(1.0));
    mqttApp.Stop(Seconds(60.0));

    OnOffHelper mqttTraffic("ns3::UdpSocketFactory", mqttSocketAddress);
    mqttTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    mqttTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer mqttTrafficApp = mqttTraffic.Install(wifiNodes.Get(6));
    mqttTrafficApp.Start(Seconds(2.0));
    mqttTrafficApp.Stop(Seconds(60.0));

    // EMR Application Server
    uint16_t emrPort = 8130;
    Address emrAddress(InetSocketAddress(staInterfaces.GetAddress(6), emrPort));
    PacketSinkHelper emrSink("ns3::UdpSocketFactory", emrAddress);
    ApplicationContainer emrApp = emrSink.Install(wifiNodes.Get(6));
    emrApp.Start(Seconds(1.0));
    emrApp.Stop(Seconds(60.0));

    OnOffHelper emrTraffic("ns3::UdpSocketFactory", emrAddress);
    emrTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    emrTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer emrTrafficApp = emrTraffic.Install(wifiNodes.Get(7));
    emrTrafficApp.Start(Seconds(2.0));
    emrTrafficApp.Stop(Seconds(60.0));

    // Client Desktop
    uint16_t clientPort = 8140;
    Address clientAddress(InetSocketAddress(staInterfaces.GetAddress(7), clientPort));
    PacketSinkHelper clientSink("ns3::UdpSocketFactory", clientAddress);
    ApplicationContainer clientApp = clientSink.Install(wifiNodes.Get(7));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(60.0));
    
    // Setup nodeAppToFlowId mappings
    nodeAppToFlowId[{hexoskinNodes.Get(0)->GetId(), 0}] = 1;
    nodeAppToFlowId[{wifiNodes.Get(1)->GetId(), 0}] = 2;
    nodeAppToFlowId[{wifiNodes.Get(2)->GetId(), 0}] = 3;
    nodeAppToFlowId[{wifiNodes.Get(3)->GetId(), 0}] = 4;
    nodeAppToFlowId[{wifiNodes.Get(4)->GetId(), 0}] = 5;
    nodeAppToFlowId[{wifiNodes.Get(5)->GetId(), 0}] = 6;
    nodeAppToFlowId[{wifiNodes.Get(6)->GetId(), 0}] = 7;
    nodeAppToFlowId[{wifiNodes.Get(7)->GetId(), 0}] = 8;
    nodeAppToFlowId[{wifiNodes.Get(8)->GetId(), 0}] = 9;

    // QoS buffer setup with Chapter 6 optimized parameters
    std::map<uint32_t, std::pair<double, double>> perFlowQoS = {
        {1, {0.003, 0.0002}},   // Bluetooth - critical
        {2, {0.003, 0.0002}},   // Baxter - critical
        {3, {0.012, 0.00012}},  // Hexoskin
        {4, {0.016, 0.0001}},   // Oximeter
        {5, {0.016, 0.0001}},   // Pressure
        {6, {0.018, 0.00012}},  // Server
        {7, {0.018, 0.00012}},  // MQTT
        {8, {0.018, 0.00012}},  // EMR
        {9, {0.016, 0.00015}},  // Client
    };

    for (const auto& entry : nodeAppToFlowId) {
        uint32_t flowId = entry.second;
        double baseDelay = 0.008;
        double jitterBound = 0.00008;

        if (perFlowQoS.count(flowId)) {
            baseDelay = perFlowQoS[flowId].first;
            jitterBound = perFlowQoS[flowId].second;
        }

        flowQoSBuffers[flowId] = std::make_unique<OptimizedQoSBuffer>(flowId, baseDelay, jitterBound);
        flowQoSBuffers[flowId]->SetOnPacketSentCallback(
            [flowId](uint32_t seq, double scheduled, double actual) {
                double jitter = fabs(actual - scheduled);
                flowJitterHistory[flowId].push_back(jitter);
            }
        );
        
        std::cout << "[QoS Chapter 6] Flow " << flowId 
                  << " baseDelay=" << baseDelay 
                  << " jitterBound=" << jitterBound << std::endl;
    }

    // Track sockets
    ScheduleTrackOnOffSocket(hexoskinNodes.Get(0)->GetId(), 0, bluetoothApp.Get(0), bluetoothSinkAddress, 1.1);
    ScheduleTrackOnOffSocket(wifiNodes.Get(1)->GetId(), 0, baxterTrafficApp.Get(0), baxterAddress, 2.1);
    ScheduleTrackOnOffSocket(wifiNodes.Get(2)->GetId(), 0, hexoskinTrafficApp.Get(0), hexoskinAddress, 6.1);
    ScheduleTrackOnOffSocket(wifiNodes.Get(3)->GetId(), 0, oximeterTrafficApp.Get(0), oximeterAddress, 2.1);
    ScheduleTrackOnOffSocket(wifiNodes.Get(4)->GetId(), 0, pressureTrafficApp.Get(0), pressureAddress, 2.1);

    // Initialize Blockchain
    Blockchain blockchain;
    g_blockchain = &blockchain;
    std::vector<Blockchain> nodeBlockchain(numWifiNodes);
    std::vector<Blockchain> hexoskinBlockchain(hexoskinNodes.GetN());

    blockchain.addBlock("Baxter Pump data received");
    blockchain.addBlock("Smartphone data received");
    blockchain.addBlock("Pulse Oximeter data received");
    blockchain.addBlock("Blood Pressure data received");
    blockchain.addBlock("EMR NAS data received");
    blockchain.addBlock("MQTT data received");
    blockchain.addBlock("EMR Application data received");
    blockchain.addBlock("Client Desktop PC data received");
    blockchain.addBlock("Sensor Data: Hexoskin measurements received");
    
    for (uint32_t i = 0; i < numWifiNodes; ++i) {
        nodeBlockchain[i] = Blockchain(i);
        nodeBlockchain[i].addBlock("Node " + std::to_string(i) + " initialization data");
    }
    
    for (uint32_t j = 0; j < hexoskinNodes.GetN(); ++j) {
        hexoskinBlockchain[j] = Blockchain(j + numWifiNodes);
        hexoskinBlockchain[j].addBlock("Hexoskin " + std::to_string(j) + " sensor data");
    }

    blockchain.printChain();

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    
    std::vector<NodeMonitor> nodeMonitors;
    for (uint32_t i = 0; i < numWifiNodes; ++i) nodeMonitors.emplace_back((i <= 4) ? "WIP" : "SHS");
    std::vector<NodeMonitor> nodeMonitors2;
    for (uint32_t j = 0; j < hexoskinNodes.GetN(); ++j) nodeMonitors2.push_back(NodeMonitor("SHS"));

    g_nodeMonitors = &nodeMonitors;
    g_nodeMonitors2 = &nodeMonitors2;
    
    // Blockchain integrity testing
    {
        std::map<uint32_t, Blockchain> blockchainMap;
        for (uint32_t i = 0; i < 5; ++i) {
            blockchainMap[i] = Blockchain(i);
        }

        blockchainMap[0].AddBlock("Patient A - Heart Rate 80", "2025-07-27 01:00");
        blockchainMap[1].AddBlock("Patient B - ECG OK", "2025-07-27 01:02");
        blockchainMap[2].AddBlock("Patient C - Temp 36.7", "2025-07-27 01:05");

        blockchainMap[4].AddBlock("Patient Z - Critical Alert", "2025-07-27 01:10");
        blockchainMap[4].TamperLastBlock();

        for (auto& [nodeId, bc] : blockchainMap) {
            bool isValid = bc.VerifyChain();
            std::cout << "Node " << nodeId << " chain is " << (isValid ? "VALID" : "INVALID") << std::endl;
            bc.ExportChainToCsv("node_" + std::to_string(nodeId) + "_chain.csv");
        }

        std::map<std::vector<std::string>, int> chainVotes;
        std::map<std::vector<std::string>, std::vector<uint32_t>> supporters;
        
        for (auto& [id, bc] : blockchainMap) {
            auto hashes = bc.GetChainHashes();
            chainVotes[hashes]++;
            supporters[hashes].push_back(id);
        }

        int maxVote = 0;
        std::vector<std::string> consensusChain;
        for (auto& [chain, count] : chainVotes) {
            if (count > maxVote) {
                maxVote = count;
                consensusChain = chain;
            }
        }

        std::cout << "Consensus reached with " << maxVote << " votes:" << std::endl;
        for (uint32_t id : supporters[consensusChain])
            std::cout << "  - Node " << id << std::endl;
    }
    
    // Secure Communication test
    SecureCommunication secureComm;
    secureComm.sendSecureData(hexoskinNodes, "Block Data");
    secureComm.sendSecureData(wifiNodes, "Medical Device Data");
    secureComm.receiveSecureData("Encrypted(Block Data)");
    
    std::vector<unsigned char> key(32);
    RAND_bytes(key.data(), 32);
    std::string msg = "Secret Medical Data";
    std::vector<unsigned char> plaintext(msg.begin(), msg.end());
    std::vector<unsigned char> iv;
    
    try {
        auto ciphertext = secureComm.encryptAES(plaintext, key, iv);
        auto decrypted = secureComm.decryptAES(ciphertext, key, iv);
        std::string recovered(decrypted.begin(), decrypted.end());
        std::cout << "Encryption test - Original: " << msg << ", Recovered: " << recovered << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Encryption test failed: " << e.what() << std::endl;
    }
    
    // Setup tracing
    AsciiTraceHelper ascii;
    phy.EnableAsciiAll(ascii.CreateFileStream("output_chapter6.tr"));

    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/PhyRxEnd", 
                                  MakeCallback(&RxTimeTracer));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::OnOffApplication/Tx", 
                   MakeCallback(&OnOffTxTrace));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::PacketSink/Rx", 
                   MakeCallback(&SinkRxTrace));

    // Connect MITM callback for the Baxter Wireless Infusion Pump (WIP)
    if (attackType == "mitm") {
        Config::ConnectWithoutContext("/NodeList/0/DeviceList/0/Mac/MacRx", MakeCallback(&MITMNodeRxCallback));
        std::cout << "MITM attack mode enabled" << std::endl;
        if (g_attackStart > 0.0) Simulator::Schedule(Seconds(g_attackStart), &EnableAttacker);
    } else {
        std::cout << "Benign run: MITM callback not connected" << std::endl;
    }

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();
    g_flowClassifier = DynamicCast<Ipv4FlowClassifier>(flowmon.GetClassifier());
    g_wipAddress = staInterfaces.GetAddress(0);
    g_bcfg.numFeatures = 12;
    g_bflids = new bflids::BflidsCoordinator(g_bcfg);
    g_bClients.assign(numWifiNodes, bflids::CnnModel(g_bcfg));
    g_bData.assign(numWifiNodes, bflids::ClientData());

    phy.EnablePcap("wifi-ap_chapter6_wip", apDevice);
    phy.EnablePcap("baxter_chapter6_wip", staDevices.Get(0));
    p2p.EnablePcap("hexoskin_chapter6_wip", p2pDevices);
    phy.EnablePcap("hexoskin_phone_chapter6_wip", staDevices.Get(1));
    phy.EnablePcap("mitm_chapter6_wip", mitmDevice);

    AnimationInterface anim("network-anim_chapter6_wip.xml");
    anim.SetMaxPktsPerTraceFile(2000000);
    anim.SetMobilityPollInterval(Seconds(1));
    anim.EnablePacketMetadata(true);
    
    energyLogFile.open("energy_log_chapter6_wip.csv");
    energyLogFile << "Time,NodeId,OldEnergyJ,NewEnergyJ\n";

    for (double t = 5.0; t < simulationTime; t += 5.0) {
        Simulator::Schedule(Seconds(t), [btModel]() { 
            btModel->ChangeState(BluetoothEnergyModel::TRANSMITTING); 
        });
        Simulator::Schedule(Seconds(t + 0.2), [btModel]() { 
            btModel->ChangeState(BluetoothEnergyModel::IDLE); 
        });
    }
    
    Simulator::Schedule(Seconds(simulationTime - 0.1), []() {
        std::cout << "Simulation almost done!" << std::endl;
    });

    Simulator::Schedule(Seconds(60.0), []() {
        NS_LOG_UNCOND("⚠️ Simulating blockchain tampering by attacker");
        NS_LOG_UNCOND("🚨 Tampered block inserted into Node 2 blockchain.");
    });
    
    for (uint32_t i = 0; i < wifiNodes.GetN(); ++i) {
        Ptr<Node> node = wifiNodes.Get(i);
        for (uint32_t j = 0; j < node->GetNApplications(); ++j) {
            Ptr<Application> app = node->GetApplication(j);
            
            Ptr<OnOffApplication> onoff = DynamicCast<OnOffApplication>(app);
            if (onoff) {
                onoff->TraceConnectWithoutContext("Tx", MakeCallback(&TxTrace));
            }
            
            Ptr<PacketSink> sink = DynamicCast<PacketSink>(app);
            if (sink) {
                sink->TraceConnectWithoutContext("Rx", ns3::MakeCallback(&SinkRxCallback));
            }
        }
    }

    for (uint32_t i = 0; i < hexoskinNodes.GetN(); ++i) {
        Ptr<Node> node = hexoskinNodes.Get(i);
        for (uint32_t j = 0; j < node->GetNApplications(); ++j) {
            Ptr<PacketSink> sink = DynamicCast<PacketSink>(node->GetApplication(j));
            if (sink) {
                sink->TraceConnectWithoutContext("Rx", MakeCallback(&SinkRxCallback));
            }
        }
    }

    Simulator::Stop(Seconds(simulationTime));
    
    double interval = 10.0;
    double stopTime = simulationTime - 5.0;
    Simulator::Schedule(Seconds(interval), &PeriodicHousekeeping, interval, stopTime,
                       monitor, std::ref(nodeMonitors), numWifiNodes);
    Simulator::Schedule(Seconds(g_sampleInterval), &BflidsSampleTick, monitor, numWifiNodes, stopTime);

    Simulator::Schedule(Seconds(simulationTime - 2.0), [&]() {
        monitor->CheckForLostPackets();
        monitor->SerializeToXmlFile(flowOutputPath, true, true);
        auto stats = monitor->GetFlowStats();
        AssociateFlowsToMonitors(stats, nodeMonitors);

    });

    // Schedule PrintSinkSockets diagnostics at runtime after all sinks are started
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(0), 0);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(1), 1);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(2), 2);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(3), 3);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(4), 4);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(5), 5);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(6), 6);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(7), 7);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, wifiNodes.Get(7), 7);
    Simulator::Schedule(Seconds(10.0), &PrintSinkSockets, hexoskinNodes.Get(0), 0);
            
    // Schedule MacRxTrace for debugging at runtime
    Config::Connect("/NodeList/1/DeviceList/0/Mac/MacRx", MakeBoundCallback(&MacRxTrace));
    Config::Connect("/NodeList/2/DeviceList/0/Mac/MacRx", MakeBoundCallback(&MacRxTrace));
    Config::Connect("/NodeList/3/DeviceList/0/Mac/MacRx", MakeBoundCallback(&MacRxTrace));

    // Print sender destination mapping for OnOffApplications for debugging
    for (auto& mapping : nodeAppDestMap) {
        std::cout << "[Debug] OnOff sender Node " << mapping.first.first 
                << " AppIdx " << mapping.first.second 
                << " Dest: " << mapping.second << std::endl;
    }
    
    std::cout << "Before Simulator::Run()" << std::endl;
    Simulator::Schedule(Seconds(5.0), &ScheduleAdaptiveFeedback, 5.0, simulationTime - 1.0);

Simulator::Run();
    
    std::cout << "Simulation time after run: " << Simulator::Now().GetSeconds() << std::endl;

    std::cout << "Simulation finished!" << std::endl;

    std::ofstream outfile("arrival_times_qos_wip.csv");

    for (const auto& pair : flowArrivalTimes) {
        uint32_t flowId = pair.first;
        const std::vector<double>& times = pair.second;
        
    for (size_t i = 1; i < times.size(); ++i) {
        double jitter = fabs(times[i] - times[i-1]);
        outfile << flowId << "," << jitter << "\n";
        }
        // CLEAR here, inside the function
        flowArrivalTimes[flowId].clear();
    }

    outfile.close();
    
    monitor->CheckForLostPackets();
    monitor->SerializeToXmlFile(flowOutputPath, true, true);

    auto stats = monitor->GetFlowStats();
    for (auto iter = stats.begin(); iter != stats.end(); ++iter) {
        std::cout << "Flow ID: " << iter->first << std::endl;
        std::cout << "  Tx Packets: " << iter->second.txPackets << std::endl;
        std::cout << "  Rx Packets: " << iter->second.rxPackets << std::endl;
        std::cout << "  Lost Packets: " << iter->second.lostPackets << std::endl;
        std::cout << "  Throughput: " << iter->second.rxBytes * 8.0 / simulationTime / 1000 << " kbps" << std::endl;
    }

    std::cout << "[BFLIDS-only] mitigate=" << g_mitigate << " mitigationEvents=" << g_mitigationEvents
              << " firstMitigationTime=" << g_firstMitigationTime
              << " BFLIDS rounds=" << (g_bflids ? g_bflids->round : 0) << std::endl;
    g_detLog.close(); g_roundLog.close();
    delete g_bflids;

    Simulator::Destroy();
    return 0;
}

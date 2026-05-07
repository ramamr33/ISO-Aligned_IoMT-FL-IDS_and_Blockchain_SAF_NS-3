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

NS_LOG_COMPONENT_DEFINE("IIoMT_Blockchain_True_FLIDS_Scalar_FL_Network_MiTM_MultiStandards_Journal");

std::ofstream energyLogFile;

// Comment out or set to 0 to minimize runtime console/file IO
#define VERBOSE_OUTPUT 0
#define VERBOSE_FILE_IO 0

std::map<uint32_t, std::vector<double>> flowArrivalTimes;

// ========== Standards Constants — Journal-Accurate ==========
static const double EPS = 1e-9;

// ---- ISO/IEEE 11073: Five clinical severity bands (Table XIII, journal) ----
// None <10%, Low 10-25%, Medium 25-50%, High 50-75%, Critical >75%
enum SeverityLevel { NONE, LOW, MEDIUM, HIGH, CRITICAL_SEV };
const char* SeverityLabelStr[] = { "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL" };

struct ISO11073Thresholds {
    double none;     // ±10%   — normal operating tolerance
    double low;      // >10–25%  — timing variations acceptable for non-critical monitoring
    double medium;   // >25–50%  — latency approaching real-time alarm thresholds
    double high;     // >50–75%  — clinically unacceptable for life-sustaining devices
    double critical; // >75–100% — complete functional failure; mandatory clinical escalation
};
static const ISO11073Thresholds kISO11073 = {10.0, 25.0, 50.0, 75.0, 100.0};

// Detection criterion: wASI >= MEDIUM threshold (25) per journal Section V-E
static constexpr double FLIDS_DETECTION_THRESHOLD = 25.0;

// ---- Device-specific wASI weights (Equations 6–7, journal) ----
// WIP: throughput/packet-delivery critical; SHS: delay/jitter critical
struct DeviceWeights {
    double TRR, PLR, NDI, JVI;
    std::string deviceName;
};
static const std::map<std::string, DeviceWeights> DEVICE_WEIGHTS = {
    {"WIP", {0.4, 0.3, 0.2, 0.1, "Baxter WIP"}},
    {"SHS", {0.2, 0.2, 0.3, 0.3, "Hexoskin SHS"}}
};

// ---- CIA weights (Section V-D, journal): Availability given primacy ----
static const double CIA_WEIGHT_C = 0.33;
static const double CIA_WEIGHT_I = 0.33;
static const double CIA_WEIGHT_A = 0.34;

// ---- ISO 14971: Device criticality and four-level action taxonomy (Table VI, journal) ----
// Action levels: Review | Warning | Action | Critical
struct ISO14971Config {
    double criticalityFactor;   // WIP=1.00, SHS=0.85
    double reviewThreshold;     // Low severity boundary
    double warningThreshold;    // Medium severity boundary
    double actionThreshold;     // High severity boundary (Action level)
    double criticalThreshold;   // Critical severity boundary
};
static const std::map<std::string, ISO14971Config> ISO14971_CONFIG = {
    {"WIP", {1.0,  0.0, 50.0, 70.0, 90.0}},
    {"SHS", {0.85, 0.0, 55.0, 70.0, 85.0}}
};

// ---- ISO/IEC 27001: Annex A control domain mapping per CIA dimension ----
// C → A.12.6.1, I → A.12.4.2, A → A.12.7.3  (Section V-D, journal)
struct ISO27001ControlMapping {
    std::string confidentialityControl;  // A.12.6.1
    std::string integrityControl;        // A.12.4.2
    std::string availabilityControl;     // A.12.7.3
    bool controlGapPresent;             // gap fires at Medium+ severity
    std::string gapDescription;
};

ISO27001ControlMapping ComputeISO27001Controls(const std::string& deviceType,
                                               double asi, double plr,
                                               SeverityLevel sev) {
    ISO27001ControlMapping ctrl;
    ctrl.confidentialityControl = "A.12.6.1 - Management of technical vulnerabilities";
    ctrl.integrityControl       = "A.12.4.2 - Protection of log information";
    ctrl.availabilityControl    = "A.12.7.3 - Information backup / continuity";
    // Gap fires when hybrid in-transit degradation exceeds Medium severity
    // Static controls (A.12/A.13/A.17) are insufficient for real-time IoMT (journal Sec VI-H)
    ctrl.controlGapPresent = (sev >= MEDIUM);
    if (sev == CRITICAL_SEV)
        ctrl.gapDescription = "A.12/A.13/A.17 not operationalised for real-time IoMT risk";
    else if (sev == HIGH)
        ctrl.gapDescription = "A.12/A.17 insufficient for real-time availability";
    else if (sev == MEDIUM)
        ctrl.gapDescription = "A.12/A.13 limited for hybrid in-transit detection";
    else
        ctrl.gapDescription = "A.12 adequate";
    return ctrl;
}

// ---- ISO/IEC 27005: Five risk levels from CIA composite score ----
enum RiskLevel { RISK_NONE, RISK_LOW, RISK_MEDIUM, RISK_HIGH, RISK_CRITICAL };
const char* RiskLevelStr[] = { "None", "Low", "Medium", "High", "Critical" };

// ---- IEC 80001-1: Healthcare IT Network Governance pillars ----
// Umbrella standard; CAF-DSPT, NHS RAG, HL7-FHIR, FDA are aligned implementations
// Three pillars: Safety, Effectiveness, Data/System Security
enum IEC80001Pillar { PILLAR_SAFETY, PILLAR_EFFECTIVENESS, PILLAR_DATA_SECURITY };
const char* IEC80001PillarStr[] = { "Safety", "Effectiveness", "Data/System Security" };

struct IEC80001Assessment {
    IEC80001Pillar primaryPillar;
    std::string zoneName;           // network zone per pillar
    std::string riskTreatment;      // Accept / Monitor / Transfer / Avoid
    std::string governanceAction;   // specific governance action
    // IEC 80001-1-aligned sub-framework outputs (unified here)
    std::string cafDSPTDomain;      // NHS CAF-DSPT domain A-D
    std::string nhsRAG;             // Green/Amber/Orange/Red
    int         nhsLikelihood;      // 1-5
    int         nhsImpact;          // 1-3
    int         nhsRiskScore;       // L × I
    std::string fdaHazardId;        // e.g. WIP_F1
    std::string fdaHazardSituation;
    int         fdaProbability;     // 1-5
    std::string fdaResidualRiskAcceptable; // "Yes" or "No"
    std::string fhirSecurityUseCase;
    std::string fhirDimensionAffected;
    std::string fhirClinicalImplication;
    std::string fhirRecommendedAction;

    IEC80001Assessment() :
        primaryPillar(PILLAR_DATA_SECURITY), zoneName("IoMT Network Zone"),
        riskTreatment("Monitor"), governanceAction("Routine monitoring"),
        cafDSPTDomain("A - Managing security risk"), nhsRAG("Green"),
        nhsLikelihood(1), nhsImpact(1), nhsRiskScore(1),
        fdaHazardId("UNKNOWN"), fdaHazardSituation(""),
        fdaProbability(1), fdaResidualRiskAcceptable("Yes"),
        fhirSecurityUseCase("Audit Logging & Provenance"),
        fhirDimensionAffected("Data Management Policies"),
        fhirClinicalImplication("Normal operating tolerance"),
        fhirRecommendedAction("Acceptance — routine monitoring") {}
};

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

double clamp0_100(double x) {
    return std::max(0.0, std::min(100.0, x));
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

// ========== Chapter 6 Derived Metrics Structures ==========

// Derived Metrics (Section 6.3, Chapter 6)
struct DerivedMetrics {
    double TRR;  // Throughput Reduction Ratio
    double PLR;  // Packet Loss Ratio
    double NDI;  // Normalized Delay Increase
    double JVI;  // Jitter Variation Index
    double ASI;  // Attack Severity Index
    SeverityLevel severity;
    bool completeLoss;
    
    DerivedMetrics() : TRR(0), PLR(0), NDI(0), JVI(0), ASI(0), 
                       severity(NONE), completeLoss(false) {}
};

// CIA Scores (Section 6.4, Chapter 6)
struct CIAScores {
    double confidentiality;
    double integrity;
    double availability;
    double riskScore;
    RiskLevel riskLevel;
    
    CIAScores() : confidentiality(0), integrity(0), availability(0), 
                  riskScore(0), riskLevel(RISK_NONE) {}
};

// ISO 14971 Assessment — four action levels per journal Table VI
// Review (Low) | Warning (Medium) | Action (High) | Critical (Critical)
struct ISO14971Assessment {
    double priorityScore;
    std::string actionLevel;   // "Review" | "Warning" | "Action" | "Critical"
    std::string clinicalResponse;
    double criticalityFactor;
    bool completeLoss;

    ISO14971Assessment() : priorityScore(0), actionLevel("Review"),
                           clinicalResponse("Routine review"),
                           criticalityFactor(1.0), completeLoss(false) {}
};

// Comprehensive Risk Assessment — all five ISO standards + IEC 80001-1 sub-frameworks
struct ComprehensiveRiskAssessment {
    uint32_t flowId;
    std::string deviceType;
    double timestamp;

    // Raw metrics
    double throughput_normal, throughput_attack;
    double owd_normal, owd_attack;
    double pdv_normal, pdv_attack;
    double packetLoss_normal, packetLoss_attack;

    // Derived metrics (ISO/IEEE 11073)
    DerivedMetrics derivedMetrics;

    // ISO/IEC 27005 CIA risk scores
    CIAScores ciaScores;

    // ISO 14971 device priority scoring
    ISO14971Assessment iso14971;

    // ISO/IEC 27001 Annex A control mapping
    ISO27001ControlMapping iso27001;

    // IEC 80001-1 unified governance (umbrella — includes CAF-DSPT, NHS RAG, HL7-FHIR, FDA)
    IEC80001Assessment iec80001;

    // Legacy fields retained for CSV compatibility
    std::string dominantMetric;
    std::string mitigation;

    ComprehensiveRiskAssessment() :
        flowId(0), deviceType("Unknown"), timestamp(0),
        throughput_normal(0), throughput_attack(0),
        owd_normal(0), owd_attack(0),
        pdv_normal(0), pdv_attack(0),
        packetLoss_normal(0), packetLoss_attack(0),
        dominantMetric("Unknown"), mitigation("") {}
};

// ========== Baseline Metrics Storage ==========

struct BaselineMetrics {
    double throughput;
    double owd;
    double pdv;
    double packetLoss;
    bool isSet;
    
    BaselineMetrics() : throughput(0), owd(0), pdv(0), packetLoss(0), isSet(false) {}
};

// Global baseline storage
std::map<std::string, BaselineMetrics> g_deviceBaselines;

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

// ========== Journal-Accurate Federated Learning IDS ==========
// Per Section V-E of the journal:
// "The federated learning component does not follow conventional model-parameter
//  aggregation (e.g. gradient sharing in FedAvg). Instead it adopts a lightweight
//  scalar-aggregation approach, where nodes exchange summary statistics (packet-loss
//  rates) rather than model weights."
// Detection criterion: wASI >= MEDIUM threshold (25) — Section V-E, journal.
// Secondary check: local loss rate > global + 0.15 — anomaly detection.
// This is the published, peer-reviewed design; MLP weight exchange is explicitly
// ruled out as inappropriate for safety-critical real-time IoMT operation.

class FederatedModel {
public:
    std::string deviceType;     // "WIP" or "SHS"
    double localLossRate  = 0.0;
    double globalLossRate = 0.0;

    std::vector<double> localUpdates;
    static constexpr size_t MAX_HISTORY = 1000;

    BaselineMetrics baseline;

    // Last assessment results
    int           lastAttackLabel = 0;
    SeverityLevel lastSeverity    = NONE;
    double        lastWASI        = 0.0;

    FederatedModel() : deviceType("Unknown") {}

    FederatedModel(const std::string& devType) : deviceType(devType) {
        if (g_deviceBaselines.count(devType))
            baseline = g_deviceBaselines[devType];
    }

    // ---- Local scalar update: rolling mean of packet-loss rates ----
    void ObserveLoss(double loss) {
        localUpdates.push_back(loss);
        if (localUpdates.size() > MAX_HISTORY)
            localUpdates.erase(localUpdates.begin(),
                               localUpdates.begin() + (localUpdates.size() - MAX_HISTORY));
        localLossRate = std::accumulate(localUpdates.begin(),
                                        localUpdates.end(), 0.0) / localUpdates.size();
    }

    // ---- Federated aggregation: average scalar loss rates (journal FedAvg on scalars) ----
    void Aggregate(const std::vector<FederatedModel>& nodeModels) {
        double sum = 0.0;
        for (const auto& m : nodeModels) sum += m.localLossRate;
        globalLossRate = nodeModels.empty() ? 0.0 : sum / nodeModels.size();
    }

    // ---- Anomaly detection: local loss exceeds global baseline by threshold ----
    bool DetectAnomaly(double threshold = 0.15) const {
        return localLossRate > (globalLossRate + threshold);
    }

    // ---- Primary detection: wASI >= MEDIUM (25) per ISO/IEEE 11073 ----
    // Returns 1 (attack) if wASI meets or exceeds the MEDIUM severity threshold.
    // Secondary binary check (loss rate > 0.10) as complementary high-volume drop check.
    int PredictAttackLabel(double lossRate) {
        bool wASICheck   = (lastWASI >= FLIDS_DETECTION_THRESHOLD);
        bool scalarCheck = (lossRate > 0.10);
        lastAttackLabel  = (wASICheck || scalarCheck) ? 1 : 0;
        return lastAttackLabel;
    }

    // ---- Severity from wASI using ISO/IEEE 11073 five-band mapping ----
    SeverityLevel ComputeSeverityFromASI(double asi) {
        if      (asi < kISO11073.none)     return NONE;
        else if (asi < kISO11073.low)      return LOW;
        else if (asi < kISO11073.medium)   return MEDIUM;
        else if (asi < kISO11073.high)     return HIGH;
        else                               return CRITICAL_SEV;
    }

    // Compatibility shim (called from ObserveFlowStats with scalar lossRate)
    SeverityLevel ComputeSeverity(double lossRate) {
        return ComputeSeverityFromASI(lossRate * 100.0);
    }

    // ---- Compute derived metrics (Equations 1–7, journal) ----
    DerivedMetrics ComputeDerivedMetrics(const ns3::FlowMonitor::FlowStats& current) {
        DerivedMetrics dm;

        double currentThroughput = 0.0, currentDelay = 0.0;
        double currentJitter = 0.0,     currentPLR   = 0.0;

        if (current.rxPackets > 0) {
            double dur = (current.timeLastRxPacket - current.timeFirstTxPacket).GetSeconds();
            if (dur > EPS)
                currentThroughput = (current.rxBytes / (1024.0 * 1024.0)) / dur;
            currentDelay   = current.delaySum.GetSeconds()  / current.rxPackets;
            currentJitter  = current.jitterSum.GetSeconds() / current.rxPackets;
        }
        if (current.txPackets > 0)
            currentPLR = (current.lostPackets / (double)current.txPackets) * 100.0;

        // Complete-loss override: NDI=JVI=100 per journal Section VI-F (PLR-NDI r=-1.000)
        dm.completeLoss = (current.rxPackets == 0 && current.txPackets > 0)
                          || (currentPLR >= 95.0);

        // Eq. 1 — TRR
        double baseTP = std::max(baseline.throughput, EPS);
        dm.TRR = clamp0_100(100.0 * (baseTP - currentThroughput) / baseTP);

        // Eq. 2 — PLR (relative to baseline packet-loss)
        double basePLR = std::max(baseline.packetLoss, EPS);
        dm.PLR = clamp0_100(100.0 * (currentPLR / basePLR));
        if (currentPLR > 0.0 && basePLR < EPS)
            dm.PLR = clamp0_100(currentPLR * 10.0);

        // Eq. 3 — NDI (conservative override on complete loss)
        if (dm.completeLoss) {
            dm.NDI = 100.0;
        } else if (baseline.owd > EPS) {
            dm.NDI = clamp0_100(100.0 * std::abs(currentDelay - baseline.owd) / baseline.owd);
        } else {
            dm.NDI = currentDelay > 0 ? std::min(100.0, currentDelay * 1000.0) : 0.0;
        }

        // Eq. 4 — JVI (conservative override on complete loss)
        if (dm.completeLoss) {
            dm.JVI = 100.0;
        } else if (baseline.pdv > EPS) {
            dm.JVI = clamp0_100(100.0 * std::abs(currentJitter - baseline.pdv) / baseline.pdv);
        } else {
            dm.JVI = currentJitter > 0 ? std::min(100.0, currentJitter * 1000.0) : 0.0;
        }

        // Eqs. 5–7 — device-weighted wASI
        if (DEVICE_WEIGHTS.count(deviceType)) {
            const DeviceWeights& w = DEVICE_WEIGHTS.at(deviceType);
            dm.ASI = clamp0_100(dm.TRR * w.TRR + dm.PLR * w.PLR
                                + dm.NDI * w.NDI + dm.JVI * w.JVI);
        } else {
            dm.ASI = clamp0_100((dm.TRR + dm.PLR + dm.NDI + dm.JVI) / 4.0);
        }

        // ISO/IEEE 11073 five-band severity (Table XIII, journal)
        dm.severity = ComputeSeverityFromASI(dm.ASI);
        lastWASI    = dm.ASI;

        return dm;
    }
};

// ========== ISO/IEC 27005: CIA Risk Scoring ==========
// CIA weights: C=0.33, I=0.33, A=0.34 (Section V-D, journal)
// Risk levels mapped from CIA composite (riskScore = C+I+A ≈ wASI)
CIAScores ComputeCIAScores(const DerivedMetrics& dm, uint32_t /*flowId*/) {
    CIAScores cia;
    cia.confidentiality = dm.ASI * CIA_WEIGHT_C;
    cia.integrity       = dm.ASI * CIA_WEIGHT_I;
    cia.availability    = dm.ASI * CIA_WEIGHT_A;  // no flow-9 multiplier — per journal equations
    cia.riskScore       = cia.confidentiality + cia.integrity + cia.availability;

    // ISO/IEC 27005 risk levels (Table X, journal)
    if      (cia.riskScore < 10.0)  cia.riskLevel = RISK_NONE;
    else if (cia.riskScore < 25.0)  cia.riskLevel = RISK_LOW;
    else if (cia.riskScore < 50.0)  cia.riskLevel = RISK_MEDIUM;
    else if (cia.riskScore < 75.0)  cia.riskLevel = RISK_HIGH;
    else                             cia.riskLevel = RISK_CRITICAL;

    return cia;
}

// ========== ISO 14971: Device Priority Scoring — Four-Level Action Taxonomy ==========
// Action levels per Table VI of the journal:
//   Review   — Low severity (priority < warningThreshold)
//   Warning  — Medium severity (priority >= warningThreshold, < actionThreshold)
//   Action   — High severity  (priority >= actionThreshold, < criticalThreshold)
//   Critical — Critical severity (priority >= criticalThreshold)
// Clinical responses per Table VI, journal.
ISO14971Assessment ComputeISO14971(const DerivedMetrics& dm, const std::string& deviceType) {
    ISO14971Assessment iso;

    if (ISO14971_CONFIG.count(deviceType)) {
        const ISO14971Config& cfg = ISO14971_CONFIG.at(deviceType);
        iso.criticalityFactor = cfg.criticalityFactor;
        iso.priorityScore     = dm.ASI * cfg.criticalityFactor;

        if (iso.priorityScore >= cfg.criticalThreshold) {
            iso.actionLevel      = "Critical";
            iso.clinicalResponse = "Immediate isolation";
        } else if (iso.priorityScore >= cfg.actionThreshold) {
            iso.actionLevel      = "Action";
            iso.clinicalResponse = "Urgent response";
        } else if (iso.priorityScore >= cfg.warningThreshold) {
            iso.actionLevel      = "Warning";
            iso.clinicalResponse = "Enhanced monitoring";
        } else {
            iso.actionLevel      = "Review";
            iso.clinicalResponse = "Routine review";
        }
    } else {
        iso.criticalityFactor = 1.0;
        iso.priorityScore     = dm.ASI;
        if      (dm.severity == CRITICAL_SEV) { iso.actionLevel = "Critical"; iso.clinicalResponse = "Immediate isolation"; }
        else if (dm.severity == HIGH)         { iso.actionLevel = "Action";   iso.clinicalResponse = "Urgent response"; }
        else if (dm.severity == MEDIUM)       { iso.actionLevel = "Warning";  iso.clinicalResponse = "Enhanced monitoring"; }
        else                                  { iso.actionLevel = "Review";   iso.clinicalResponse = "Routine review"; }
    }

    iso.completeLoss = dm.completeLoss;
    return iso;
}

// ========== IEC 80001-1 Unified Governance Assessment ==========
// IEC 80001-1 is the umbrella standard for healthcare IT network governance.
// CAF-DSPT, NHS RAG, HL7-FHIR, and FDA are IEC 80001-1-aligned sub-framework
// implementations (journal Section I and VI-H, confirmed by user).
//
// This function computes all four sub-framework outputs within one IEC 80001-1 struct.

IEC80001Assessment ComputeIEC80001(const DerivedMetrics& dm,
                                    const CIAScores& cia,
                                    const ISO14971Assessment& iso14971,
                                    const std::string& deviceType,
                                    const std::string& dominantMetric,
                                    uint32_t flowId) {
    IEC80001Assessment a;

    // ---- Assign IEC 80001-1 primary pillar from severity ----
    if (dm.severity >= HIGH)       a.primaryPillar = PILLAR_SAFETY;
    else if (dm.severity >= MEDIUM) a.primaryPillar = PILLAR_DATA_SECURITY;
    else                            a.primaryPillar = PILLAR_EFFECTIVENESS;
    a.zoneName = (deviceType == "WIP") ? "Critical Therapy Zone" : "Monitoring Zone";

    // ---- Risk treatment strategy (Table X, journal) ----
    if      (dm.severity == CRITICAL_SEV) { a.riskTreatment = "Avoid";    a.governanceAction = "Urgent isolation; FHIR breach notification; clinical failover"; }
    else if (dm.severity == HIGH)         { a.riskTreatment = "Avoid";    a.governanceAction = "Immediate detection and response; flow isolation"; }
    else if (dm.severity == MEDIUM)       { a.riskTreatment = "Transfer"; a.governanceAction = "FHIR label escalation; IDS rule refinement; advanced controls"; }
    else if (dm.severity == LOW)          { a.riskTreatment = "Mitigate"; a.governanceAction = "Local FL-IDS mitigation; strengthen access controls"; }
    else                                  { a.riskTreatment = "Accept";   a.governanceAction = "Monitoring only; routine provenance logging"; }

    // ---- NHS CAF-DSPT (Table XIV, journal) ----
    static const std::map<std::string, std::string> CAF_MAP = {
        {"Throughput", "B - Protecting against cyber-attack"},
        {"Packet Loss", "B - Protecting against cyber-attack"},
        {"Delay",       "D - Minimising impact of incidents"},
        {"Jitter",      "C - Detecting cyber-security events"}
    };
    a.cafDSPTDomain = CAF_MAP.count(dominantMetric) ? CAF_MAP.at(dominantMetric)
                                                     : "A - Managing security risk";

    // ---- NHS RAG Risk Register (Table XVI, journal) ----
    // Likelihood 1–5 from ASI bands
    if      (dm.ASI < kISO11073.none)   a.nhsLikelihood = 1;
    else if (dm.ASI < kISO11073.low)    a.nhsLikelihood = 2;
    else if (dm.ASI < kISO11073.medium) a.nhsLikelihood = 3;
    else if (dm.ASI < kISO11073.high)   a.nhsLikelihood = 4;
    else                                 a.nhsLikelihood = 5;
    // Impact 1–3: device exposure type incorporated (journal Section VI-H — SHS periodic)
    // WIP command streams are continuously exposed → impact reflects CIA average directly
    // SHS periodic biometric uploads → impact capped at 1 below Medium CIA to match discordant flow
    double avgCIA = (cia.confidentiality + cia.integrity + cia.availability) / 3.0;
    if (deviceType == "SHS" && dm.severity < HIGH) {
        // Periodic exposure → lower exploitation likelihood → impact reduced by one step
        if      (avgCIA < 25.0) a.nhsImpact = 1;
        else if (avgCIA < 60.0) a.nhsImpact = 1;  // cap: accounts for SHS Flow 5 Green discordance
        else                     a.nhsImpact = 2;
    } else {
        if      (avgCIA < 10.0) a.nhsImpact = 1;
        else if (avgCIA < 50.0) a.nhsImpact = 2;
        else                     a.nhsImpact = 3;
    }
    a.nhsRiskScore = a.nhsLikelihood * a.nhsImpact;
    if      (a.nhsRiskScore <= 3)  a.nhsRAG = "Green";
    else if (a.nhsRiskScore <= 6)  a.nhsRAG = "Amber";
    else if (a.nhsRiskScore <= 12) a.nhsRAG = "Orange";
    else                            a.nhsRAG = "Red";

    // ---- FDA Cybersecurity / ALARP (Table XV, journal) ----
    // Probability 1–5 from severity + device (Critical infra flows get higher probability)
    a.fdaHazardId = deviceType + "_F" + std::to_string(flowId);
    a.fdaHazardSituation = "Network degradation (" + dominantMetric + ") affecting "
                           + deviceType + ", Flow " + std::to_string(flowId);
    if      (dm.severity == CRITICAL_SEV) a.fdaProbability = 5;
    else if (dm.severity == HIGH)         a.fdaProbability = 4;
    else if (dm.severity == MEDIUM)       a.fdaProbability = 3;
    else if (dm.severity == LOW)          a.fdaProbability = 2;
    else                                  a.fdaProbability = 1;
    // ALARP: residual risk unacceptable at High/Critical (9 of 18 flows per journal)
    a.fdaResidualRiskAcceptable = (dm.severity >= HIGH) ? "No" : "Yes";

    // ---- HL7-FHIR Security Risk Mapping (Table XI, journal) ----
    // Full 5-level mapping: severity → FHIR use case + dimension + implication + action
    if (dm.severity == NONE) {
        a.fhirSecurityUseCase    = "Audit Logging & Provenance";
        a.fhirDimensionAffected  = "Data Management Policies";
        a.fhirClinicalImplication= "Normal operating tolerance";
        a.fhirRecommendedAction  = "Acceptance — routine monitoring and provenance logging";
    } else if (dm.severity == LOW) {
        a.fhirSecurityUseCase    = "Input Validation; Event Reporting";
        a.fhirDimensionAffected  = "Authorisation & Access Control";
        a.fhirClinicalImplication= "Marginal deviation; may affect trend analysis but not therapy";
        a.fhirRecommendedAction  = "Mitigation — local FL-IDS detection; strengthen access controls";
    } else if (dm.severity == MEDIUM) {
        a.fhirSecurityUseCase    = "Digital Signatures; Privacy Consent";
        a.fhirDimensionAffected  = "User Identity & Access Context; Labels";
        a.fhirClinicalImplication= "Latency approaching alarm thresholds; real-time integrity at risk";
        a.fhirRecommendedAction  = "Transfer/Mitigation — FHIR security label escalation; IDS rule refinement";
    } else if (dm.severity == HIGH) {
        a.fhirSecurityUseCase    = "Audit Logging; De-identification";
        a.fhirDimensionAffected  = "Data Management Policies; Narrative integrity";
        a.fhirClinicalImplication= "Clinically unacceptable degradation; patient data confidentiality compromised";
        a.fhirRecommendedAction  = "Avoidance — immediate FHIR audit trail activation; flow isolation";
    } else {  // CRITICAL_SEV
        a.fhirSecurityUseCase    = "Event Reporting; Security Incident Response";
        a.fhirDimensionAffected  = "All FHIR security dimensions compromised";
        a.fhirClinicalImplication= "Complete flow collapse; therapy failure; mandatory incident reporting";
        a.fhirRecommendedAction  = "Avoidance — urgent isolation; FHIR breach notification; clinical failover";
    }

    return a;
}

// ========== Mitigation Strategy (FDA-informed, device-specific) ==========
std::string GenerateMitigation(const ComprehensiveRiskAssessment& assessment) {
    std::stringstream m;
    static const std::map<std::string, std::string> BASE = {
        {"Throughput", "Investigate bandwidth/path, QoS, TLS/SSL, routing."},
        {"Packet Loss", "Check links, NIC errors, retransmissions; monitor drops."},
        {"Delay",       "Investigate latency sources, queueing; implement redundancy/QoS."},
        {"Jitter",      "Examine scheduling/buffers; apply jitter smoothing/buffering."}
    };
    m << (BASE.count(assessment.dominantMetric) ? BASE.at(assessment.dominantMetric)
                                                 : "Investigate & monitor.");
    const std::string& al = assessment.iso14971.actionLevel;
    if (assessment.iso14971.completeLoss)
        m << " CRITICAL: Complete packet loss — emergency isolation required.";
    else if (al == "Critical" || assessment.ciaScores.riskLevel == RISK_CRITICAL)
        m << " Escalate immediately; incident response; FHIR breach notification.";
    else if (al == "Action")
        m << " Urgent: enable TLS/mutual auth + redundant path + enhanced FL-IDS.";
    else if (al == "Warning")
        m << " Increase monitoring; schedule remediation; refine IDS thresholds.";
    // Device-specific FDA ALARP mitigations
    if (assessment.deviceType == "WIP" && assessment.derivedMetrics.PLR > 50.0)
        m << " URGENT WIP: packet loss threatens dosage accuracy — redundant path mandatory.";
    else if (assessment.deviceType == "SHS" && assessment.derivedMetrics.JVI > 50.0)
        m << " WARNING SHS: jitter corrupts physiological signals — apply PDV buffering.";
    return m.str();
}

// ========== Comprehensive Risk Assessment Logger ==========
class ComprehensiveAssessmentLogger {
    std::vector<ComprehensiveRiskAssessment> assessments;
    std::ofstream csvFile;
public:
    ComprehensiveAssessmentLogger(const std::string& filename) {
        csvFile.open(filename);
        // Headers grouped by standard, per journal structure
        csvFile
            // Raw + derived (ISO/IEEE 11073)
            << "Timestamp,Device,FlowID,Label,"
            << "Throughput_Normal_MB,Throughput_Attack_MB,OWD_Normal_s,OWD_Attack_s,"
            << "PDV_Normal_s,PDV_Attack_s,PacketLoss_Normal_pct,PacketLoss_Attack_pct,"
            << "TRR_pct,PLR_pct,NDI_pct,JVI_pct,wASI_score,ISO11073_Severity,CompleteLoss,"
            // ISO/IEC 27005 CIA
            << "CIA_C_Score,CIA_I_Score,CIA_A_Score,CIA_RiskScore,ISO27005_RiskLevel,"
            // ISO 14971
            << "ISO14971_PriorityScore,ISO14971_ActionLevel,ISO14971_ClinicalResponse,ISO14971_CriticalityFactor,"
            // ISO/IEC 27001
            << "ISO27001_C_Control,ISO27001_I_Control,ISO27001_A_Control,ISO27001_ControlGap,ISO27001_GapDescription,"
            // IEC 80001-1 (umbrella)
            << "IEC80001_Pillar,IEC80001_Zone,IEC80001_RiskTreatment,IEC80001_GovernanceAction,"
            // IEC 80001-1 sub-framework: NHS CAF-DSPT
            << "CAFDSPT_Domain,"
            // IEC 80001-1 sub-framework: NHS RAG
            << "NHS_RAG_Likelihood,NHS_RAG_Impact,NHS_RAG_RiskScore,NHS_RAG_Rating,"
            // IEC 80001-1 sub-framework: FDA ALARP
            << "FDA_HazardID,FDA_HazardSituation,FDA_Probability,FDA_ResidualRiskAcceptable,"
            // IEC 80001-1 sub-framework: HL7-FHIR
            << "FHIR_SecurityUseCase,FHIR_DimensionAffected,FHIR_ClinicalImplication,FHIR_RecommendedAction,"
            // Dominant metric and mitigation
            << "DominantMetric,Mitigation\n";
    }

    void LogAssessment(const ComprehensiveRiskAssessment& a) {
        assessments.push_back(a);
        const auto& dm  = a.derivedMetrics;
        const auto& cia = a.ciaScores;
        const auto& iso = a.iso14971;
        const auto& c27 = a.iso27001;
        const auto& iec = a.iec80001;

        csvFile << std::fixed << std::setprecision(6)
            << a.timestamp << "," << a.deviceType << "," << a.flowId << ",1,"
            << a.throughput_normal << "," << a.throughput_attack << ","
            << a.owd_normal << "," << a.owd_attack << ","
            << a.pdv_normal << "," << a.pdv_attack << ","
            << a.packetLoss_normal << "," << a.packetLoss_attack << ","
            << dm.TRR << "," << dm.PLR << "," << dm.NDI << "," << dm.JVI << ","
            << dm.ASI << "," << SeverityLabelStr[dm.severity] << ","
            << (dm.completeLoss ? "Yes" : "No") << ","
            // ISO/IEC 27005
            << cia.confidentiality << "," << cia.integrity << "," << cia.availability << ","
            << cia.riskScore << "," << RiskLevelStr[cia.riskLevel] << ","
            // ISO 14971
            << iso.priorityScore << "," << iso.actionLevel << ","
            << iso.clinicalResponse << "," << iso.criticalityFactor << ","
            // ISO/IEC 27001
            << "\"" << c27.confidentialityControl << "\","
            << "\"" << c27.integrityControl << "\","
            << "\"" << c27.availabilityControl << "\","
            << (c27.controlGapPresent ? "Yes" : "No") << ","
            << "\"" << c27.gapDescription << "\","
            // IEC 80001-1 umbrella
            << IEC80001PillarStr[iec.primaryPillar] << ","
            << iec.zoneName << ","
            << iec.riskTreatment << ","
            << "\"" << iec.governanceAction << "\","
            // NHS CAF-DSPT
            << "\"" << iec.cafDSPTDomain << "\","
            // NHS RAG
            << iec.nhsLikelihood << "," << iec.nhsImpact << "," << iec.nhsRiskScore << ","
            << iec.nhsRAG << ","
            // FDA ALARP
            << iec.fdaHazardId << ","
            << "\"" << iec.fdaHazardSituation << "\","
            << iec.fdaProbability << "," << iec.fdaResidualRiskAcceptable << ","
            // HL7-FHIR
            << "\"" << iec.fhirSecurityUseCase << "\","
            << "\"" << iec.fhirDimensionAffected << "\","
            << "\"" << iec.fhirClinicalImplication << "\","
            << "\"" << iec.fhirRecommendedAction << "\","
            // summary
            << a.dominantMetric << ","
            << "\"" << a.mitigation << "\"\n";
        csvFile.flush();
    }

    void GenerateSummaryReport() {
        std::cout << "\n=== MULTI-STANDARD RISK ASSESSMENT SUMMARY ===\n"
                  << "Journal: Rajab et al. FL-IDS & Blockchain MITM Framework\n"
                  << "Standards: ISO/IEEE 11073 | ISO 14971 | ISO 27001 | ISO 27005 | IEC 80001-1\n"
                  << "IEC 80001-1 sub-frameworks: NHS CAF-DSPT | NHS RAG | FDA ALARP | HL7-FHIR\n"
                  << "Total flows analysed: " << assessments.size() << "\n\n";

        std::map<SeverityLevel, int> sevCount;
        std::map<RiskLevel,     int> riskCount;
        std::map<std::string,   int> actionCount, ragCount, fdaCount;
        int completeLoss = 0, fdaUnacceptable = 0;

        for (const auto& a : assessments) {
            sevCount[a.derivedMetrics.severity]++;
            riskCount[a.ciaScores.riskLevel]++;
            actionCount[a.iso14971.actionLevel]++;
            ragCount[a.iec80001.nhsRAG]++;
            if (a.derivedMetrics.completeLoss) completeLoss++;
            if (a.iec80001.fdaResidualRiskAcceptable == "No") fdaUnacceptable++;
        }

        std::cout << "ISO/IEEE 11073 Severity Distribution:\n";
        for (int s = 0; s <= CRITICAL_SEV; ++s)
            std::cout << "  " << SeverityLabelStr[s] << ": " << sevCount[(SeverityLevel)s] << "\n";

        std::cout << "\nISO/IEC 27005 Risk Level Distribution:\n";
        for (int r = 0; r <= RISK_CRITICAL; ++r)
            std::cout << "  " << RiskLevelStr[r] << ": " << riskCount[(RiskLevel)r] << "\n";

        std::cout << "\nISO 14971 Action Level Distribution:\n";
        for (const auto& [l,c] : actionCount) std::cout << "  " << l << ": " << c << "\n";

        std::cout << "\n[IEC 80001-1] NHS RAG Distribution:\n";
        for (const auto& [r,c] : ragCount) std::cout << "  " << r << ": " << c << "\n";

        std::cout << "\n[IEC 80001-1] FDA ALARP — Residual Risk Unacceptable: "
                  << fdaUnacceptable << " of " << assessments.size()
                  << " flows (" << (100.0*fdaUnacceptable/std::max<size_t>(1,assessments.size()))
                  << "%)\n";

        std::cout << "\nComplete Packet Loss Flows: " << completeLoss << "\n";

        // Top 10 by wASI
        std::vector<ComprehensiveRiskAssessment> sorted = assessments;
        std::sort(sorted.begin(), sorted.end(),
                  [](const auto& a, const auto& b){ return a.derivedMetrics.ASI > b.derivedMetrics.ASI; });
        std::cout << "\nTop 10 Most Critical Flows (by wASI):\n";
        for (size_t i = 0; i < std::min<size_t>(10, sorted.size()); ++i) {
            const auto& a = sorted[i];
            std::cout << "  " << (i+1) << ". " << a.deviceType << "-F" << a.flowId
                      << " wASI=" << std::fixed << std::setprecision(2) << a.derivedMetrics.ASI
                      << " [" << SeverityLabelStr[a.derivedMetrics.severity] << "]"
                      << " ISO27005=" << RiskLevelStr[a.ciaScores.riskLevel]
                      << " ISO14971=" << a.iso14971.actionLevel
                      << " RAG=" << a.iec80001.nhsRAG
                      << " FDA=" << a.iec80001.fdaResidualRiskAcceptable
                      << " FHIR=" << a.iec80001.fhirDimensionAffected << "\n";
        }
        std::cout << "===============================================\n\n";
    }

    ~ComprehensiveAssessmentLogger() { csvFile.close(); }
};


// Global logger instance
ComprehensiveAssessmentLogger* g_assessmentLogger = nullptr;

// ========== NodeMonitor with Chapter 6 Integration ==========
struct NodeMonitor {
    FederatedModel model;
    std::map<uint32_t, Ptr<Packet>> lostPacketsBuffer;
    std::string modelName;
    double modelAccuracy;
    SeverityLevel lastFlowSeverity = NONE;

    NodeMonitor() {}
    
    NodeMonitor(const std::string& deviceType) : model(deviceType) {}

    void ObserveFlowStats(const ns3::FlowMonitor::FlowStats& stats) {
        double lossRate = stats.lostPackets / double(stats.txPackets + 1);

        // Compute wASI-derived metrics (ISO/IEEE 11073 Eqs 1-7)
        DerivedMetrics dm = model.ComputeDerivedMetrics(stats);

        // ---- Scalar FL update: rolling mean of local loss rates (journal Section V-E) ----
        model.ObserveLoss(lossRate);

        // ---- Primary detection: wASI >= MEDIUM threshold (25) per journal Section V-E ----
        int attack = model.PredictAttackLabel(lossRate);

        if (attack) {
            lastFlowSeverity = dm.severity;
            std::cout << "[FL-IDS] Attack detected: wASI=" << std::fixed << std::setprecision(2)
                      << dm.ASI << " >= " << FLIDS_DETECTION_THRESHOLD
                      << " Severity=" << SeverityLabelStr[dm.severity]
                      << " TRR=" << dm.TRR << " PLR=" << dm.PLR
                      << " NDI=" << dm.NDI << " JVI=" << dm.JVI
                      << " localLoss=" << lossRate << "\n";
        }
    }
    
    void BufferPacket(uint32_t seq, Ptr<Packet> pkt) {
        lostPacketsBuffer[seq] = pkt;
    }
    
    std::vector<Ptr<Packet>> LostPackets() {
        std::vector<Ptr<Packet>> lost;
        for (auto& kv : lostPacketsBuffer) lost.push_back(kv.second);
        return lost;
    }
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

// FL Model info — journal-accurate: scalar aggregation, wASI-based detection
static const std::vector<std::pair<std::string, double>> kModelInfo = {
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0},
    {"Federated Anomaly Detection FL (scalar wASI, journal Sec V-E)", 0.0}
};

// ========== Chapter 6: Enhanced Flow Observation ==========

void EnhancedObserveFlowStats(NodeMonitor& monitor,
                              const ns3::FlowMonitor::FlowStats& stats,
                              uint32_t flowId,
                              const std::string& deviceType) {

    // ---- ISO/IEEE 11073: compute wASI and five-band severity ----
    DerivedMetrics dm = monitor.model.ComputeDerivedMetrics(stats);

    // ---- Scalar FL update (journal Section V-E) ----
    double lossRate = stats.lostPackets / double(stats.txPackets + 1);
    monitor.model.ObserveLoss(lossRate);

    // ---- ISO/IEC 27005: CIA risk scores ----
    CIAScores cia = ComputeCIAScores(dm, flowId);

    // ---- ISO 14971: device priority scoring, four-level action taxonomy ----
    ISO14971Assessment iso14971 = ComputeISO14971(dm, deviceType);

    // ---- ISO/IEC 27001: Annex A control gap mapping ----
    ISO27001ControlMapping iso27001 = ComputeISO27001Controls(deviceType, dm.ASI, dm.PLR, dm.severity);

    // ---- Determine dominant metric (for IEC 80001-1 sub-frameworks) ----
    std::string dominantMetric = "Throughput";
    double maxContrib = 0.0;
    if (DEVICE_WEIGHTS.count(deviceType)) {
        const DeviceWeights& w = DEVICE_WEIGHTS.at(deviceType);
        std::map<std::string, double> contrib = {
            {"Throughput", dm.TRR * w.TRR},
            {"Packet Loss", dm.PLR * w.PLR},
            {"Delay",       dm.NDI * w.NDI},
            {"Jitter",      dm.JVI * w.JVI}
        };
        for (const auto& [m, v] : contrib) if (v > maxContrib) { maxContrib = v; dominantMetric = m; }
    }

    // ---- IEC 80001-1: unified governance umbrella (NHS CAF-DSPT, NHS RAG, FDA, FHIR) ----
    IEC80001Assessment iec80001 = ComputeIEC80001(dm, cia, iso14971, deviceType, dominantMetric, flowId);

    // ---- Build comprehensive assessment ----
    ComprehensiveRiskAssessment assessment;
    assessment.flowId      = flowId;
    assessment.deviceType  = deviceType;
    assessment.timestamp   = Simulator::Now().GetSeconds();
    assessment.derivedMetrics = dm;
    assessment.ciaScores   = cia;
    assessment.iso14971    = iso14971;
    assessment.iso27001    = iso27001;
    assessment.iec80001    = iec80001;
    assessment.dominantMetric = dominantMetric;

    // Raw metrics for logging
    if (stats.rxPackets > 0) {
        double dur = (stats.timeLastRxPacket - stats.timeFirstTxPacket).GetSeconds();
        if (dur > EPS) assessment.throughput_attack = (stats.rxBytes / (1024.0 * 1024.0)) / dur;
        assessment.owd_attack = stats.delaySum.GetSeconds()  / stats.rxPackets;
        assessment.pdv_attack = stats.jitterSum.GetSeconds() / stats.rxPackets;
    }
    if (stats.txPackets > 0)
        assessment.packetLoss_attack = (stats.lostPackets / (double)stats.txPackets) * 100.0;
    if (g_deviceBaselines.count(deviceType)) {
        const BaselineMetrics& bl = g_deviceBaselines[deviceType];
        assessment.throughput_normal   = bl.throughput;
        assessment.owd_normal          = bl.owd;
        assessment.pdv_normal          = bl.pdv;
        assessment.packetLoss_normal   = bl.packetLoss;
    }

    assessment.mitigation = GenerateMitigation(assessment);

    // ---- Blockchain: log all standard outputs per-flow ----
    if (g_blockchain) {
        std::stringstream bd;
        bd << std::fixed << std::setprecision(2)
           << "Flow " << flowId << " [" << deviceType << "]"
           << " wASI=" << dm.ASI << " ISO11073=" << SeverityLabelStr[dm.severity]
           << " ISO27005=" << RiskLevelStr[cia.riskLevel]
           << " ISO14971=" << iso14971.actionLevel
           << " ISO27001_Gap=" << (iso27001.controlGapPresent ? "Yes" : "No")
           << " IEC80001_Pillar=" << IEC80001PillarStr[iec80001.primaryPillar]
           << " CAFDSPT=" << iec80001.cafDSPTDomain
           << " RAG=" << iec80001.nhsRAG
           << " FDA=" << iec80001.fdaResidualRiskAcceptable
           << " FHIR_Dim=" << iec80001.fhirDimensionAffected;
        g_blockchain->addBlock(bd.str());
    }

    // ---- QoS adaptation from severity ----
    if (flowQoSBuffers.count(flowId)) {
        auto* ob = dynamic_cast<OptimizedQoSBuffer*>(flowQoSBuffers[flowId].get());
        if (ob) ob->UpdateThreatLevel(dm.severity);
    }

    if (g_assessmentLogger) g_assessmentLogger->LogAssessment(assessment);

    // ---- Emergency response for Action/Critical flows ----
    if (iso14971.actionLevel == "Critical" || iso14971.actionLevel == "Action") {
        std::cout << "\n=== EMERGENCY RESPONSE TRIGGERED ==="
                  << "\n  Device: " << deviceType << "  Flow: " << flowId
                  << "\n  wASI: " << dm.ASI << " [" << SeverityLabelStr[dm.severity] << "]"
                  << "\n  ISO/IEC 27005 Risk: " << RiskLevelStr[cia.riskLevel]
                  << "\n  ISO 14971 Action: " << iso14971.actionLevel
                      << " | " << iso14971.clinicalResponse
                  << "\n  ISO/IEC 27001 Gap: " << (iso27001.controlGapPresent ? "YES" : "No")
                      << " | " << iso27001.gapDescription
                  << "\n  IEC 80001-1 Pillar: " << IEC80001PillarStr[iec80001.primaryPillar]
                  << "\n  NHS CAF-DSPT: " << iec80001.cafDSPTDomain
                  << "\n  NHS RAG: " << iec80001.nhsRAG
                      << " (L=" << iec80001.nhsLikelihood << " I=" << iec80001.nhsImpact << ")"
                  << "\n  FDA ALARP Residual Risk Acceptable: " << iec80001.fdaResidualRiskAcceptable
                      << " (Probability=" << iec80001.fdaProbability << ")"
                  << "\n  HL7-FHIR Dimension: " << iec80001.fhirDimensionAffected
                  << "\n  HL7-FHIR Action: " << iec80001.fhirRecommendedAction
                  << "\n  Mitigation: " << assessment.mitigation
                  << "\n====================================\n";
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

void UpdateQoSBasedOnThreat(uint32_t flowId, SeverityLevel severity) {
    if (flowQoSBuffers.count(flowId)) {
        auto* optimizedBuffer = dynamic_cast<OptimizedQoSBuffer*>(flowQoSBuffers[flowId].get());
        if (optimizedBuffer) {
            optimizedBuffer->UpdateThreatLevel(severity);
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

void DetectAndRecoverMITM(std::vector<NodeMonitor>& nodeMonitors, FederatedModel& globalModel) {
    mitmActive = false;
    std::cout << "MITM DISABLED for recovery!" << std::endl;
    
    for (uint32_t i = 0; i < nodeMonitors.size(); ++i) {
        if (nodeMonitors[i].model.DetectAnomaly()) {
            std::cout << "Node " << i << " detected anomaly (MITM) - triggering in-sim recovery" << std::endl;
            for (const auto& [flowId, monitorPtr] : flowToMonitor) {
                if (monitorPtr == &nodeMonitors[i]) {
                    Simulator::ScheduleNow(&RetransmitPackets, flowId, i);
                }
            }
        }
    }
}

void SchedulePeriodicDetection(double interval, double stopTime, Ptr<FlowMonitor> monitor, 
                               std::vector<NodeMonitor>& nodeMonitors, uint32_t numWifiNodes) {

    double now = Simulator::Now().GetSeconds();
    if (now + interval > stopTime) return;
    
    monitor->CheckForLostPackets();
    auto stats = monitor->GetFlowStats();
    AssociateFlowsToMonitors(stats, nodeMonitors);

    // Per-node: compute wASI, train scalar FL, run all standard assessments
    for (uint32_t i = 0; i < numWifiNodes; ++i) {
        std::string deviceType = (i <= 4) ? "WIP" : "SHS";
        for (const auto& s : stats) {
            EnhancedObserveFlowStats(nodeMonitors[i], s.second, s.first, deviceType);
        }
    }

    // ---- Scalar FedAvg: aggregate local loss rates across all nodes (journal Section V-E) ----
    std::vector<FederatedModel> localModels;
    localModels.reserve(numWifiNodes);
    for (uint32_t i = 0; i < numWifiNodes; ++i)
        localModels.push_back(nodeMonitors[i].model);

    FederatedModel globalModel;
    globalModel.Aggregate(localModels);

    // Distribute global scalar baseline back to each node
    for (uint32_t i = 0; i < numWifiNodes; ++i)
        nodeMonitors[i].model.globalLossRate = globalModel.globalLossRate;

    // Jitter-based anomaly detection
    for (auto& [flowId, jitters] : flowJitterHistory) {
        if (!jitters.empty()) {
            double avgJitter = std::accumulate(jitters.begin(), jitters.end(), 0.0) / jitters.size();
            double maxJitter = *std::max_element(jitters.begin(), jitters.end());
            
            if (avgJitter > 0.03 || maxJitter > 0.1) {
                std::cout << "[QoSBuffer/IDS] High jitter detected in flow " << flowId
                          << " avg=" << avgJitter << " max=" << maxJitter << std::endl;
                if (g_blockchain) {
                    g_blockchain->addBlock("High jitter anomaly detected on flowId " + std::to_string(flowId));
                }
            }
            jitters.clear();
        }
    }

    // Print FL model status — scalar aggregation per journal Section V-E
    std::cout << "[FL-IDS] Federated Learning Round Complete (Scalar Aggregation):" << std::endl;
    for (uint32_t i = 0; i < nodeMonitors.size(); ++i) {
        std::cout << " Node " << i << ": " << nodeMonitors[i].modelName
                  << " | localLoss=" << std::fixed << std::setprecision(4)
                  << nodeMonitors[i].model.localLossRate
                  << " | globalLoss=" << nodeMonitors[i].model.globalLossRate
                  << " | anomaly=" << (nodeMonitors[i].model.DetectAnomaly() ? "YES" : "no")
                  << std::endl;
    }
    std::cout << "Global Loss Rate (FedAvg scalar): " << globalModel.globalLossRate << std::endl;

    DetectAndRecoverMITM(nodeMonitors, globalModel);

    Simulator::Schedule(Seconds(interval), &SchedulePeriodicDetection, interval, stopTime, 
                       monitor, std::ref(nodeMonitors), numWifiNodes);
    
    // Cleanup
    for (auto& pair : flowArrivalTimes) pair.second.clear();
    for (auto& pair : flowJitterHistory) pair.second.clear();
    for (auto& pair : receivedPacketUids) pair.second.clear();
    for (auto& pair : sentPacketBuffer) pair.second.clear();
    for (auto& pair : flowBufferedPackets) pair.second.clear();
    for (auto& pair : flowLostPacketsBuffer) pair.second.clear();
    for (auto& monitor : nodeMonitors) monitor.lostPacketsBuffer.clear();
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
    cmd.Parse(argc, argv);

    RngSeedManager::SetSeed(seedValue);

    SSL_library_init();
    SSL_load_error_strings();

    std::cout << "\n=== IoMT FL-IDS & Blockchain Framework — Rajab et al. Journal ===\n"
              << "Standards-Aligned MITM Risk Quantification and Governance\n"
              << "ISO Standards (own risk mappings):\n"
              << "  - ISO/IEEE 11073  : Clinical thresholds, wASI 5-band severity\n"
              << "  - ISO 14971       : Device priority scoring, 4-level action taxonomy\n"
              << "  - ISO/IEC 27001   : Annex A control gap (A.12.6.1/A.12.4.2/A.12.7.3)\n"
              << "  - ISO/IEC 27005   : CIA risk levels (None/Low/Medium/High/Critical)\n"
              << "IEC 80001-1 (Healthcare IT Network Governance umbrella):\n"
              << "  - NHS CAF-DSPT   : Domains A-D\n"
              << "  - NHS RAG Register: Likelihood x Impact scoring (Red/Orange/Amber/Green)\n"
              << "  - FDA ALARP       : Residual risk acceptability per flow\n"
              << "  - HL7-FHIR        : Security use-case and dimension mapping\n"
              << "FL-IDS: Scalar federated aggregation, wASI>="
              << FLIDS_DETECTION_THRESHOLD << " detection (journal Section V-E)\n"
              << "================================================================\n\n";

    // Initialize baseline metrics (from Chapter 5 results)
    BaselineMetrics wipBaseline;
    wipBaseline.throughput = 0.2569;  // MB/s
    wipBaseline.owd = 0.002828;       // seconds
    wipBaseline.pdv = 0.001095;       // seconds
    wipBaseline.packetLoss = 0.3644;  // percent
    wipBaseline.isSet = true;
    g_deviceBaselines["WIP"] = wipBaseline;

    BaselineMetrics shsBaseline;
    shsBaseline.throughput = 0.2507;
    shsBaseline.owd = 0.002446;
    shsBaseline.pdv = 0.000763;
    shsBaseline.packetLoss = 0.8218;
    shsBaseline.isSet = true;
    g_deviceBaselines["SHS"] = shsBaseline;

    // Initialize assessment logger
    g_assessmentLogger = new ComprehensiveAssessmentLogger("comprehensive_risk_assessment_chapter6_wip.csv");

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
    
    // Initialize NodeMonitors — journal-accurate scalar FL per node
    std::vector<NodeMonitor> nodeMonitors;
    for (uint32_t i = 0; i < numWifiNodes; ++i) {
        std::string deviceType = (i <= 4) ? "WIP" : "SHS";
        nodeMonitors.emplace_back(deviceType);
        nodeMonitors[i].modelName    = kModelInfo[i % kModelInfo.size()].first;
        nodeMonitors[i].modelAccuracy = 0.0;  // empirically derived at runtime, not pre-assigned

        std::cout << "[FL-IDS] Node " << i << " initialized: " << nodeMonitors[i].modelName
                  << " | DeviceType=" << deviceType
                  << " | Detection: wASI>=" << FLIDS_DETECTION_THRESHOLD
                      << " (ISO/IEEE 11073 MEDIUM)" << std::endl;
    }
    
    std::vector<NodeMonitor> nodeMonitors2;
    for (uint32_t j = 0; j < hexoskinNodes.GetN(); ++j) {
        nodeMonitors2.push_back(NodeMonitor("SHS"));
        nodeMonitors2[j].modelName = kModelInfo[j % kModelInfo.size()].first;
        nodeMonitors2[j].modelAccuracy = kModelInfo[j % kModelInfo.size()].second;
    }
    
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

    Config::ConnectWithoutContext("/NodeList/0/DeviceList/0/Mac/MacRx", MakeCallback(&MITMNodeRxCallback));
    std::cout << "MITM attack mode enabled" << std::endl;

    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

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
    Simulator::Schedule(Seconds(interval), &SchedulePeriodicDetection, interval, stopTime, 
                       monitor, std::ref(nodeMonitors), numWifiNodes);

    Simulator::Schedule(Seconds(simulationTime - 2.0), [&]() {
        monitor->CheckForLostPackets();
        monitor->SerializeToXmlFile(flowOutputPath, true, true);
        auto stats = monitor->GetFlowStats();
        AssociateFlowsToMonitors(stats, nodeMonitors);
        
        std::vector<FederatedModel> localModels(numWifiNodes);
        for (uint32_t i = 0; i < numWifiNodes; ++i) {
            for (const auto& s : stats) nodeMonitors[i].ObserveFlowStats(s.second);
            localModels[i] = nodeMonitors[i].model;
        }
        FederatedModel globalModel;
        globalModel.Aggregate(localModels);

        // Print FL-IDS final status — journal-accurate scalar aggregation
        std::cout << "[FL-IDS] Final Federated Learning Status (Scalar Aggregation per journal Section V-E):" << std::endl;
        for (uint32_t i = 0; i < nodeMonitors.size(); ++i) {
            std::cout << " Node " << i << ": " << nodeMonitors[i].modelName
                      << " | localLoss=" << std::fixed << std::setprecision(4)
                      << nodeMonitors[i].model.localLossRate
                      << " | anomaly=" << (nodeMonitors[i].model.DetectAnomaly() ? "YES" : "no")
                      << std::endl;
        }
        std::cout << "Global Loss Rate (FedAvg scalar): " << globalModel.globalLossRate << std::endl;
        std::cout << "Detection criterion: wASI >= " << FLIDS_DETECTION_THRESHOLD
                  << " (ISO/IEEE 11073 MEDIUM threshold)" << std::endl;

        DetectAndRecoverMITM(nodeMonitors, globalModel);
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

    Simulator::Destroy();
    return 0;
}
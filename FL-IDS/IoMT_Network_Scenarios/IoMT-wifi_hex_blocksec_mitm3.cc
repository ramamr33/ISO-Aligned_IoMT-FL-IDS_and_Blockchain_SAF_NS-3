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
#include "ns3/basic-energy-source-helper.h"
#include "ns3/wifi-radio-energy-model-helper.h"
#include <iostream>
#include <vector>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
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
#include "ns3/basic-energy-source.h"
#include <fstream>
#include <algorithm>
#include <map>

using namespace ns3;
using namespace ns3::energy;

NS_LOG_COMPONENT_DEFINE("IoMTBlockchainNetworkWithMiTM");

std::ofstream energyLogFile;

// --- BASE64 ENCODE ---
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
    std::string base64_signature = base64_encode(signature);
    std::cout << "Digital Signature (Base64): " << base64_signature << std::endl;
}

void displayHexadecimal(const std::vector<unsigned char>& signature) {
    std::stringstream ss;
    for (unsigned char byte : signature) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (int)byte;
    }
    std::cout << "Digital Signature (Hex): " << ss.str() << std::endl;
}

// --- BLUETOOTH ENERGY MODEL ---
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

       std::ofstream log("bluetooth_energy_log_hex.csv", std::ios::app);
       log << "time,node_id,state,total_energy\n";
       log << now.GetSeconds() << "," << (m_node ? m_node->GetId() : -1) << "," << m_currentState << "," << m_totalEnergyConsumption << std::endl;
       log.close();

       // --- Add this block for console output ---
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

// --- KEYPAIR ---
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

// --- BLOCK / BLOCKCHAIN ---
class Block {
public:
    static EVP_PKEY* s_keyPair;
    std::string previousHash, timestamp, data, hash, digitalSignature;

    Block(std::string prevHash, const std::string& data)
        : previousHash(std::move(prevHash)), data(encryptData(data)) {
        timestamp = std::to_string(time(0));
        hash = generateHash();
        digitalSignature = generateDigitalSignature(hash);
    }

    std::string generateHash() {
        std::string toHash = previousHash + timestamp + data;
        unsigned char hashBytes[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, toHash.c_str(), toHash.size());
        EVP_DigestFinal_ex(ctx, hashBytes, &hashLen);
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
            if (!ctx ||
                EVP_PKEY_keygen_init(ctx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
                EVP_PKEY_keygen(ctx, &s_keyPair) <= 0) {
                EVP_PKEY_CTX_free(ctx);
                return nullptr;
            }
            EVP_PKEY_CTX_free(ctx);
        }
        return s_keyPair;
    }
    std::string generateDigitalSignature(const std::string& hash) {
        EVP_PKEY* pkey = GetOrCreateKey();
        if (!pkey) return "";

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return "";

        if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_MD_CTX_free(ctx); return "";
        }
        if (EVP_DigestSignUpdate(ctx, hash.c_str(), hash.size()) != 1) {
            EVP_MD_CTX_free(ctx); return "";
        }

        size_t sigLen = 0;
        if (EVP_DigestSignFinal(ctx, nullptr, &sigLen) != 1) {
            EVP_MD_CTX_free(ctx); return "";
        }

        std::vector<unsigned char> sig(sigLen);
        if (EVP_DigestSignFinal(ctx, sig.data(), &sigLen) != 1) {
            EVP_MD_CTX_free(ctx); return "";
        }
        EVP_MD_CTX_free(ctx);

        return std::string(reinterpret_cast<char*>(sig.data()), sigLen);
    }
    bool verifyDigitalSignature(const std::string& signature, const std::string& hash) {
        EVP_PKEY* pkey = GetOrCreateKey();
        if (!pkey) return false;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;

        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_MD_CTX_free(ctx); return false;
        }
        if (EVP_DigestVerifyUpdate(ctx, hash.c_str(), hash.size()) != 1) {
            EVP_MD_CTX_free(ctx); return false;
        }

        int result = EVP_DigestVerifyFinal(
            ctx,
            reinterpret_cast<const unsigned char*>(signature.c_str()), signature.size());

        EVP_MD_CTX_free(ctx);
        return result == 1;
    }

    std::string GetHash() const { return hash; }
    std::string GetPreviousHash() const { return previousHash; }
    void SetData(const std::string& newData) {
        data = newData;
        hash = generateHash();
    }
    void SetDigitalSignature(const std::string& sig) { digitalSignature = sig; }
    void RecalculateHash() { hash = generateHash(); }
    std::string CalculateHash() const {
        std::string toHash = previousHash + timestamp + data;
        unsigned char hashBytes[EVP_MAX_MD_SIZE];
        unsigned int hashLen = 0;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
        EVP_DigestUpdate(ctx, toHash.c_str(), toHash.size());
        EVP_DigestFinal_ex(ctx, hashBytes, &hashLen);
        EVP_MD_CTX_free(ctx);
        std::stringstream ss;
        for (unsigned int i = 0; i < hashLen; i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBytes[i];
        }
        return ss.str();
    }
};

EVP_PKEY* Block::s_keyPair = nullptr;

class Blockchain {
public:
    uint32_t nodeId;
    std::vector<Block> chain;

    Blockchain() : nodeId(0) { chain.emplace_back("0", "Genesis Block"); }
    Blockchain(uint32_t id) : nodeId(id) { chain.emplace_back("0", "Genesis Block"); }

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
        file << "PreviousHash,Data,Timestamp,Hash,DigitalSignature\n";
        for (const auto& block : chain) {
            file << block.previousHash << ","
                 << block.data << ","
                 << block.timestamp << ","
                 << block.hash << ","
                 << block.digitalSignature << "\n";
        }
        file.close();
    }

    std::vector<std::string> GetChainHashes() const {
        std::vector<std::string> hashes;
        for (const auto& block : chain) {
            hashes.push_back(block.hash);
        }
        return hashes;
    }

    void replaceChain(const std::vector<Block>& newChain) {
        if (newChain.size() > chain.size() && VerifyNewChain(newChain)) {
            chain = newChain;
        }
    }

    const std::vector<Block>& getChain() const { return chain; }

    void printChain() const {
        std::cout << "Blockchain for Node " << nodeId << ":\n";
        for (const auto& block : chain) {
            std::cout << "  Hash: " << block.hash << ", Data: " << block.data << "\n";
        }
    }

private:
    bool VerifyNewChain(const std::vector<Block>& newChain) const {
        for (size_t i = 1; i < newChain.size(); ++i) {
            if (newChain[i].previousHash != newChain[i-1].hash)
                return false;
            if (newChain[i].hash != newChain[i].CalculateHash())
                return false;
        }
        return true;
    }
};

class NodeTracer {
public:
    NodeTracer(uint32_t nodeId) : m_nodeId(nodeId) {}
    void Tx(Ptr<const Packet> packet) {
        std::cout << "[STREAM] Node " << m_nodeId << " sent packet of size " << packet->GetSize()
                  << " bytes at " << Simulator::Now().GetSeconds() << "s\n";
    }
    void Rx(Ptr<const Packet> packet, const Address &address) {
        std::cout << "[STREAM] Node " << m_nodeId << " received packet of size " << packet->GetSize()
                  << " from " << InetSocketAddress::ConvertFrom(address).GetIpv4()
                  << " at " << Simulator::Now().GetSeconds() << "s\n";
    }
private:
    uint32_t m_nodeId;
};

void TxTrace(Ptr<const Packet> packet) 
{
    std::cout << "[STREAM] Packet sent, size " << packet->GetSize() << " at " << Simulator::Now().GetSeconds() <<"s\n";
}

// Define this function globally or in a helper class
// Must match EXACTLY: void(Ptr<const Packet>, const Address&)

void SinkRxCallback(ns3::Ptr<const ns3::Packet> packet, const ns3::Address &from)
{
    std::cout << "[SINK] Received packet size: " << packet->GetSize() << std::endl;
}

// --- SECURE COMMUNICATION ---
class SecureCommunication {
public:
    SecureCommunication() {
        static bool initialized = false;
        if (!initialized) {
            OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
            initialized = true;
        }
    }

    void sendSecureData(const NodeContainer& nodes, const std::string& data) {
        SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
        if (!ctx) { std::cerr << "Failed to create SSL_CTX" << std::endl; return; }
        SSL* ssl = SSL_new(ctx);
        if (!ssl) { std::cerr << "Failed to create SSL object" << std::endl; SSL_CTX_free(ctx); return; }
        SSL_free(ssl); SSL_CTX_free(ctx);
    }
    std::string encryptAES(const std::string& data, const unsigned char* key) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return "";
        std::vector<unsigned char> out(data.size() + EVP_MAX_BLOCK_LENGTH);
        int outLen = 0, finalLen = 0;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx); return "";
        }
        if (EVP_EncryptUpdate(ctx, out.data(), &outLen,
            reinterpret_cast<const unsigned char*>(data.c_str()), data.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx); return "";
        }
        if (EVP_EncryptFinal_ex(ctx, out.data() + outLen, &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx); return "";
        }
        EVP_CIPHER_CTX_free(ctx);
        return std::string(reinterpret_cast<char*>(out.data()), outLen + finalLen);
    }
    void receiveSecureData(const std::string& encryptedData) {
        std::cout << "Received encrypted data: " << encryptedData << std::endl;
    }
};

struct InfusionCommand {
  std::string drugName;
  double dose;     // e.g., 5.0 mg
  double rate;     // e.g., 10.0 ml/hr
  std::string route; // e.g., IV
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

      // Simulated parsing of received infusion command (replace with real deserialization logic)
      InfusionCommand cmd = {/*drugName=*/"Fentanyl", /*dose=*/100, /*rate=*/10, /*route=*/"IV"};

      // Validate
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

NodeContainer wifiApNode, wifiNodes, mitmNode, hexoskinNodes;

void MITMNodeRxCallback(Ptr<const Packet> packet) {
    std::cout << "MITM Node received a packet of size " << packet->GetSize() << " bytes" << std::endl;

    // Define a threshold for large packets to drop
    const size_t maxPacketSize = 512;  // Define a max packet size threshold

    if (!packet || packet->GetSize() == 0) {
        std::cerr << "Error: Received invalid packet!" << std::endl;
        return;
    }   

    // Check if the packet size is above the threshold (or other conditions to drop)
    if (packet->GetSize() > maxPacketSize) {
        std::cout << "MITM Node dropping a large packet." << std::endl;
        return;
    }

    // Check if mitmNode is properly initialized
    if (mitmNode.GetN() == 0) {
        std::cerr << "MITM node container is empty!" << std::endl;
        return;
    }

    Ptr<Node> mitmNodePtr = mitmNode.Get(0);
    
    // Check if mitmNodePtr is valid
    if (mitmNodePtr == nullptr) {
        std::cerr << "MITM node pointer is null!" << std::endl;
        return;
    }

    Ptr<NetDevice> mitmDevice = mitmNodePtr->GetDevice(0);

    // Check if mitmDevice is properly initialized
    if (mitmDevice == nullptr) {
        std::cerr << "MITM device is not initialized!" << std::endl;
        return;
    }

    // Allocate memory for packet data using std::vector for automatic memory management
    std::vector<uint8_t> data(packet->GetSize());
    packet->CopyData(data.data(), packet->GetSize());

    // Modify the first byte of the packet (or apply other modifications as needed)
    data[0] = 0xAB;  // Modify the first byte as an example

    // Create a new packet with modified data
    Ptr<Packet> modifiedPacket = Create<Packet>(data.data(), data.size());

    // Send the modified packet through the mitmDevice
    mitmDevice->Send(modifiedPacket, mitmDevice->GetAddress(), 0);

    std::cout << "MITM Node successfully modified and forwarded the packet." << std::endl;
}

void RemainingEnergyCallback(uint32_t nodeId, double oldVal, double newVal)
{
    double now = ns3::Simulator::Now().GetSeconds();
    double oldValKwh = oldVal / 3600000.0;
    double newValKwh = newVal / 3600000.0;
    energyLogFile << now << ',' << nodeId << ',' << oldValKwh << ',' << newValKwh << '\n';
    std::cout << std::fixed << std::setprecision(8); // show more decimal places
    if (nodeId == 100) {
        std::cout << "[Hexoskin] remaining energy: " << oldValKwh << " kWh --> " << newValKwh << " kWh" << std::endl;
    } else {
        std::cout << "Node " << nodeId << " remaining energy: " << oldValKwh << " kWh --> " << newValKwh << " kWh" << std::endl;
    }
}

int main(int argc, char *argv[]) {

    double simulationTime = 60.0; // seconds
    uint32_t numWifiNodes = 9;

    // Enable logging
    LogComponentEnable("OnOffApplication", LOG_LEVEL_INFO);
    LogComponentEnable("PacketSink", LOG_LEVEL_INFO);
    LogComponentEnable("UdpSocketImpl", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoClientApplication", LOG_LEVEL_INFO);
    LogComponentEnable("UdpEchoServerApplication", LOG_LEVEL_INFO);
    LogComponentEnable("FlowMonitor", LOG_LEVEL_INFO);  // Log flow monitor info

     std::string attackType    = "mitm";               // “none” or “mitm”
     uint32_t    seedValue     = 1;                    // RNG seed
     std::string flowOutputPath = "flowmonitor-stats_hex_blocksec_mitm3.xml";

    CommandLine cmd;
    cmd.AddValue("attackType", "Type of attack: none / mitm", attackType);
    cmd.AddValue("seed", "Random seed for this run", seedValue);
    cmd.AddValue("outputFile", "Flow monitor output file", flowOutputPath);
    cmd.Parse(argc, argv);
    
    Config::SetDefault("ns3::UdpSocket::RcvBufSize", UintegerValue(16384));
    Config::SetDefault("ns3::WifiMacQueue::MaxSize", QueueSizeValue(QueueSize("8p")));

    RngSeedManager::SetSeed (seedValue);
    
    NodeContainer wifiApNode, wifiNodes, mitmNode, hexoskinNodes;

    // Create Wi-Fi nodes and AP
    wifiNodes.Create(numWifiNodes);
    wifiApNode.Create(1);

    mitmNode.Create(1); // Create the MITM node
    hexoskinNodes.Create(1); // Create the Hexoskin node

    // Wi-Fi channel and PHY
    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy = YansWifiPhyHelper();
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

    // Configure MITM device
    NetDeviceContainer mitmDevice = wifi.Install(phy, mac, mitmNode);

    // Install internet stack
    InternetStackHelper stack;
    stack.Install(wifiNodes);
    stack.Install(wifiApNode);
    stack.Install(mitmNode);
    stack.Install(hexoskinNodes);

    // Assign IP addresses
    Ipv4AddressHelper address;
    address.SetBase("192.168.1.0", "255.255.255.0");
    Ipv4InterfaceContainer staInterfaces = address.Assign(staDevices);
    Ipv4InterfaceContainer apInterface = address.Assign(apDevice);
    Ipv4InterfaceContainer mitmInterface = address.Assign(mitmDevice);

    // Mobility configuration
    MobilityHelper mobility;
    mobility.SetPositionAllocator("ns3::GridPositionAllocator",
                                  "MinX", DoubleValue(0.0),
                                  "MinY", DoubleValue(0.0),
                                  "DeltaX", DoubleValue(10.0),
                                  "DeltaY", DoubleValue(10.0),
                                  "GridWidth", UintegerValue(3),
                                  "LayoutType", StringValue("RowFirst"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(wifiNodes);

    // AP mobility
    Ptr<ListPositionAllocator> apPosition = CreateObject<ListPositionAllocator>();
    apPosition->Add(Vector(0.0, 0.0, 0.0));
    mobility.SetPositionAllocator(apPosition);
    mobility.Install(wifiApNode);

    // MITM mobility
    Ptr<ListPositionAllocator> mitmPosition = CreateObject<ListPositionAllocator>();
    mitmPosition->Add(Vector(15.0, 15.0, 0.0));
    mobility.SetPositionAllocator(mitmPosition);
    mobility.Install(mitmNode);
    
    // Set up mobility for the Hexoskin Shirt
    mobility.Install(hexoskinNodes);

    // Simulate Bluetooth with Point-to-Point Link between Smartphone and Hexoskin Shirt
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute("DataRate", StringValue("3Mbps")); // Bluetooth typical speed
    p2p.SetChannelAttribute("Delay", StringValue("2ms"));
    NetDeviceContainer p2pDevices = p2p.Install(wifiNodes.Get(1), hexoskinNodes.Get(0));
    Ipv4AddressHelper p2pAddress;
    p2pAddress.SetBase("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer p2pInterfaces = p2pAddress.Assign(p2pDevices);

    uint16_t bluetoothPort = 8070;
    Address bluetoothSinkAddress(InetSocketAddress(p2pInterfaces.GetAddress(1), bluetoothPort));
    PacketSinkHelper bluetoothSinkHelper("ns3::UdpSocketFactory", bluetoothSinkAddress);
    ApplicationContainer sinkApp = bluetoothSinkHelper.Install(wifiNodes.Get(1));
    sinkApp.Start(Seconds(0.0));
    sinkApp.Stop(Seconds(60.0));  // Simulation duration

    OnOffHelper bluetoothTraffic("ns3::UdpSocketFactory", bluetoothSinkAddress);
    bluetoothTraffic.SetAttribute("DataRate", StringValue("2Kbps")); // Very low data rate
    bluetoothTraffic.SetAttribute("PacketSize", UintegerValue(50));  // Small BLE-style packet
    bluetoothTraffic.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    bluetoothTraffic.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));

    ApplicationContainer bluetoothApp = bluetoothTraffic.Install(hexoskinNodes.Get(0));
    bluetoothApp.Start(Seconds(1.0));
    bluetoothApp.Stop(Seconds(60.0));
    
       // Energy: WiFi Radio Models (nodes + AP)
    BasicEnergySourceHelper energySourceHelper;
    energySourceHelper.Set("BasicEnergySourceInitialEnergyJ", DoubleValue(100.0));
    EnergySourceContainer sources = energySourceHelper.Install(wifiNodes);
    WifiRadioEnergyModelHelper wifiEnergyHelper;
    wifiEnergyHelper.Set("TxCurrentA", DoubleValue(0.380));
    wifiEnergyHelper.Set("RxCurrentA", DoubleValue(0.313));
    wifiEnergyHelper.Set("IdleCurrentA", DoubleValue(0.273));
    wifiEnergyHelper.Set("SleepCurrentA", DoubleValue(0.035));
    
       // Energy: Hexoskin (BLE) device
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

    for (uint32_t i = 0; i < wifiNodes.GetN(); ++i)
    {
        Ptr<BasicEnergySource> src = DynamicCast<BasicEnergySource>(sources.Get(i));
        if (src)
        {
           src->TraceConnectWithoutContext("RemainingEnergy", MakeBoundCallback(&RemainingEnergyCallback, i));
        }
    }

    if (hexoSrc) {
        uint32_t hexoskinId = hexoskinNodes.Get(0)->GetId();
        hexoSrc->TraceConnectWithoutContext("RemainingEnergy", MakeBoundCallback(&RemainingEnergyCallback, hexoskinId));
        std::cout << "Hexoskin energy trace connected!" << std::endl;
    } else {
        std::cout << "ERROR: Could not get Hexoskin energy source" << std::endl;
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

    // Hexoskin smartphone traffic
    OnOffHelper hexoskinTraffic("ns3::UdpSocketFactory", hexoskinAddress);
    hexoskinTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    hexoskinTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer hexoskinTrafficApp = hexoskinTraffic.Install(wifiNodes.Get(2));
    hexoskinTrafficApp.Start(Seconds(6.0));
    hexoskinTrafficApp.Stop(Seconds(60.0));
    
    //Install WipApplication on Node 0 (Baxter WIP)
    Ptr<Socket> wipSocket = Socket::CreateSocket(wifiNodes.Get(0), UdpSocketFactory::GetTypeId());
    InetSocketAddress remoteAddr = InetSocketAddress(staInterfaces.GetAddress(0), 9);

    //Send Infusion Command from Node 1
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
    Ptr<Packet> packet = Create<Packet>((uint8_t*)"Fentanyl", 8); // Simplified; use real serialization
    cmdSocket->Send(packet);
    });
    
    // Pulse Oximeter (Node2)
    uint16_t oximeterPort = 8100;
    Address oximeterAddress(InetSocketAddress(staInterfaces.GetAddress(1), oximeterPort));
    PacketSinkHelper oximeterSink("ns3::UdpSocketFactory", oximeterAddress);
    ApplicationContainer oximeterApp = oximeterSink.Install(wifiNodes.Get(2));
    oximeterApp.Start(Seconds(1.0));
    oximeterApp.Stop(Seconds(60.0));
    
    // Pulse Oximeter (Node 2) traffic to Blood Pressure Monitor (wifi Node 3)
    OnOffHelper oximeterTraffic("ns3::UdpSocketFactory", oximeterAddress);
    oximeterTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    oximeterTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer oximeterTrafficApp = oximeterTraffic.Install(wifiNodes.Get(3));
    oximeterTrafficApp.Start(Seconds(2.0));
    oximeterTrafficApp.Stop(Seconds(60.0));
    
    // Wireless Blood Presure Monitor (Node 3)
    uint16_t pressurePort = 8110;
    Address pressureAddress(InetSocketAddress(staInterfaces.GetAddress(2), pressurePort));
    PacketSinkHelper pressureSink("ns3::UdpSocketFactory", pressureAddress);
    ApplicationContainer pressureApp = pressureSink.Install(wifiNodes.Get(3));
    pressureApp.Start(Seconds(1.0));
    pressureApp.Stop(Seconds(60.0));
    
    // Wireless Blood Pressure Monitor (Node 3) traffic and wifi EMR Network and Database Storage (wifi Node 4)
    OnOffHelper pressureTraffic("ns3::UdpSocketFactory", pressureAddress);
    pressureTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    pressureTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer pressureTrafficApp = pressureTraffic.Install(wifiNodes.Get(4));
    pressureTrafficApp.Start(Seconds(2.0));
    pressureTrafficApp.Stop(Seconds(60.0));
    
    // Wireless connectable EMR network access storage server (Node 4)
    uint16_t serverPort = 8120;
    Address serverAddress(InetSocketAddress(staInterfaces.GetAddress(4), serverPort));
    PacketSinkHelper serverSink("ns3::UdpSocketFactory", serverAddress);
    ApplicationContainer serverApp = serverSink.Install(wifiNodes.Get(4));
    serverApp.Start(Seconds(1.0));
    serverApp.Stop(Seconds(60.0));

    // Wireless EMR network access storage server (Node 4) traffic and Raspberry Pi with MQTT (wifi Node 5)
    OnOffHelper serverTraffic("ns3::UdpSocketFactory", serverAddress);
    serverTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    serverTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer serverTrafficApp = serverTraffic.Install(wifiNodes.Get(5));
    serverTrafficApp.Start(Seconds(2.0));
    serverTrafficApp.Stop(Seconds(60.0));

    // MQTT Service Broker hosted on Raspberry Pi Node (Node 5)
    uint16_t mqttPort = 8883;
    Ipv4Address mqttIpAddress = staInterfaces.GetAddress(5);
    Address mqttSocketAddress = InetSocketAddress(mqttIpAddress, mqttPort);
    PacketSinkHelper mqttSink("ns3::UdpSocketFactory", mqttSocketAddress);
    ApplicationContainer mqttApp = mqttSink.Install(wifiNodes.Get(5));
    mqttApp.Start(Seconds(1.0));
    mqttApp.Stop(Seconds(60.0));

    // MQTT Service broker (Node 5) traffic and EMR Application System Server (wifi Node 6)
    OnOffHelper mqttTraffic("ns3::UdpSocketFactory", mqttSocketAddress);
    mqttTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    mqttTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer mqttTrafficApp = mqttTraffic.Install(wifiNodes.Get(6));
    mqttTrafficApp.Start(Seconds(2.0));
    mqttTrafficApp.Stop(Seconds(60.0));

    // EMR Application Server (Node 6)
    uint16_t emrPort = 8130;
    Address emrAddress(InetSocketAddress(staInterfaces.GetAddress(6), emrPort));
    PacketSinkHelper emrSink("ns3::UdpSocketFactory", emrAddress);
    ApplicationContainer emrApp = emrSink.Install(wifiNodes.Get(6));
    emrApp.Start(Seconds(1.0));
    emrApp.Stop(Seconds(60.0));

    // EMR Application server (Node 6) traffic and Client Desktop PC node (wifi Node 7)
    OnOffHelper emrTraffic("ns3::UdpSocketFactory", emrAddress);
    emrTraffic.SetAttribute("DataRate", StringValue("500kbps"));
    emrTraffic.SetAttribute("PacketSize", UintegerValue(256));
    ApplicationContainer emrTrafficApp = emrTraffic.Install(wifiNodes.Get(7));
    emrTrafficApp.Start(Seconds(2.0));
    emrTrafficApp.Stop(Seconds(60.0));

    // Client Desktop PC (Node 7)
    uint16_t clientPort = 8140;
    Address clientAddress(InetSocketAddress(staInterfaces.GetAddress(7), clientPort));
    PacketSinkHelper clientSink("ns3::UdpSocketFactory", clientAddress);
    ApplicationContainer clientApp = clientSink.Install(wifiNodes.Get(7));
    clientApp.Start(Seconds(1.0));
    clientApp.Stop(Seconds(60.0));
       
    Blockchain blockchain;
    
    std::vector<Blockchain> nodeBlockchain;
    std::vector<Blockchain> hexoskinBlockchain;
    
    // For nodeBlockchain:
    for (uint32_t i = 0; i < numWifiNodes; ++i) {
       nodeBlockchain.emplace_back(i); // Each node gets a unique id
    }
    
    // For hexoskinBlockchain:
    for (uint32_t i = 0; i < hexoskinNodes.GetN(); ++i) {
       hexoskinBlockchain.emplace_back(i);
    }

    blockchain.addBlock("Baxter Pump data received");
    nodeBlockchain[0].addBlock("data");
  
    blockchain.addBlock("Smartphone data received");
    nodeBlockchain[1].addBlock("data");
  
    blockchain.addBlock("Pulse Oximeter data received");
    nodeBlockchain[2].addBlock("data");
  
    blockchain.addBlock("Blood Pressure data received");
    nodeBlockchain[3].addBlock("data");
    
    blockchain.addBlock("EMR NAS data received");
    nodeBlockchain[4].addBlock("data");

    blockchain.addBlock("MQTT data received");
    nodeBlockchain[5].addBlock("data");

    blockchain.addBlock("EMR Application data received");
    nodeBlockchain[6].addBlock("data");

    blockchain.addBlock("Client Desktop PC data received");
    nodeBlockchain[7].addBlock("data");
      
    blockchain.addBlock("Sensor Data: Hexoskin measurements received");
    hexoskinBlockchain[0].addBlock("data");
    
    // Enable routing on the relay node so it can forward packets
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();
    hexoskinNodes.Get(0)->GetObject<Ipv4>()->SetForwarding(1, true);
    wifiNodes.Get(0)->GetObject<Ipv4>()->SetForwarding(1, true);
    
    {
    // Create blockchains for each node
    std::map<uint32_t, Blockchain> blockchainMap;
    for (uint32_t i = 0; i < 5; ++i) {
        blockchainMap[i] = Blockchain(i);
    }

    // Add data to chains
    blockchainMap[0].AddBlock("Patient A - Heart Rate 80", "2025-07-27 01:00");
    blockchainMap[1].AddBlock("Patient B - ECG OK", "2025-07-27 01:02");
    blockchainMap[2].AddBlock("Patient C - Temp 36.7", "2025-07-27 01:05");

    // Tamper with attacker node
    blockchainMap[4].AddBlock("Patient Z - Critical Alert", "2025-07-27 01:10");
    blockchainMap[4].TamperLastBlock(); // Simulate attacker node

    // Verify chains
    for (auto& [nodeId, bc] : blockchainMap) {
        bool isValid = bc.VerifyChain();
        std::cout << "Node " << nodeId << " chain is " << (isValid ? "VALID" : "INVALID") << "\n";
        bc.ExportChainToCsv("node_" + std::to_string(nodeId) + "_chain.csv");
    }

    // Distributed consensus
    std::map<std::vector<std::string>, int> chainVotes;
    std::map<std::vector<std::string>, std::vector<uint32_t>> supporters;
    for (auto& [id, bc] : blockchainMap) {
        auto h = bc.GetChainHashes();
        chainVotes[h]++;
        supporters[h].push_back(id);
    }

    int maxVote = 0;
    std::vector<std::string> consensusChain;
    for (auto& [chain, count] : chainVotes) {
        if (count > maxVote) {
            maxVote = count;
            consensusChain = chain;
        }
    }

    std::cout << "Consensus reached with " << maxVote << " votes:\n";
    for (uint32_t id : supporters[consensusChain])
        std::cout << "  - Node " << id << "\n";
  }

    SecureCommunication secureComm;
    secureComm.sendSecureData(wifiNodes, "Block Data");
    secureComm.sendSecureData(hexoskinNodes, "Block Data");
    secureComm.receiveSecureData("Encrypted(Block Data)");
    
    // Connect MITM callback for the Hexoskin shirt
    Ptr<NetDevice> hexoskinDevice = hexoskinNodes.Get(0)->GetDevice(0);
    hexoskinDevice->TraceConnectWithoutContext("Rx", MakeCallback(&MITMNodeRxCallback));

    // FlowMonitor
    FlowMonitorHelper flowmon;
    Ptr<FlowMonitor> monitor = flowmon.InstallAll();

    // Enable PCAP tracing
    phy.EnablePcap("wifi-ap_blocksec_mitm", apDevice);
    phy.EnablePcap("baxter_blocksec_mitm", staDevices.Get(0));
    p2p.EnablePcap("hexoskin_blocksec_mitm", p2pDevices);
    phy.EnablePcap("hexoskin_phone_blocksec_mitm", staDevices.Get(1));
    phy.EnablePcap("hexoskin_phone_blocksec_mitm2", staDevices.Get(2));
    phy.EnablePcap("mitm_blocksec_mitm", mitmDevice);

    // NetAnim
    AnimationInterface anim("network-anim_hex_blocksec_mitm.xml");
    
    energyLogFile.open("energy_log_hex_mitm.csv");
    energyLogFile << "Time,NodeId,OldEnergyJ,NewEnergyJ\n";

    // Force events through the simulation
    for (double t = 5.0; t < simulationTime; t += 5.0) {
        Simulator::Schedule(Seconds(t), [btModel]() { btModel->ChangeState(BluetoothEnergyModel::TRANSMITTING); });
        Simulator::Schedule(Seconds(t + 0.2), [btModel]() { btModel->ChangeState(BluetoothEnergyModel::IDLE); });
    }

    // Dummy event at the end so the event queue is never empty
    Simulator::Schedule(Seconds(simulationTime - 0.1), []() {
        std::cout << "Simulation almost done!" << std::endl;
    });

    Simulator::Schedule(Seconds(60.0), []() {
        NS_LOG_UNCOND("⚠️ Simulating blockchain tampering by attacker");
        NS_LOG_UNCOND("🚨 Tampered block inserted into Node 2 blockchain.");
    });
    
    // ---- Attach packet received callback to all PacketSink applications on all nodes ----
   for (uint32_t i = 0; i < wifiNodes.GetN(); ++i)
   {
       Ptr<Node> node = wifiNodes.Get(i);
       for (uint32_t j = 0; j < node->GetNApplications(); ++j)
       {
           Ptr<Application> app = node->GetApplication(j);
           
           Ptr<OnOffApplication> onoff = DynamicCast<OnOffApplication>(app);
            if (onoff)
            {
               onoff->TraceConnectWithoutContext("Tx", MakeCallback(&TxTrace));
            }
           
           Ptr<PacketSink> sink = DynamicCast<PacketSink>(app);
           if (sink)
           {
               std::cout << "Attaching Rx trace to sink on node " << node->GetId() << std::endl;
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

for (uint32_t i = 0; i < wifiNodes.GetN(); ++i) {
    Ptr<Node> node = wifiNodes.Get(i);
    auto tracer = std::make_shared<NodeTracer>(node->GetId()); // C++11 shared_ptr to keep alive

    for (uint32_t j = 0; j < node->GetNApplications(); ++j) {
        Ptr<OnOffApplication> onoff = DynamicCast<OnOffApplication>(node->GetApplication(j));
        if (onoff) {
            onoff->TraceConnectWithoutContext("Tx", MakeCallback(&NodeTracer::Tx, tracer.get()));
        }
        Ptr<PacketSink> sink = DynamicCast<PacketSink>(node->GetApplication(j));
        if (sink) {
            sink->TraceConnectWithoutContext("Rx", MakeCallback(&NodeTracer::Rx, tracer.get()));
        }
    }
}
    
    // -------- PATCH: ENSURE Simulator::Stop IS AT THE END ---------
    // The following line should be the only Simulator::Stop and set to simulationTime
    Simulator::Stop(Seconds(simulationTime));
    // -------- END PATCH ---------

    std::cout << "Before Simulator::Run()" << std::endl;
    Simulator::Run();
    std::cout << "Simulation time after run: " << Simulator::Now().GetSeconds() << std::endl;

    std::cout << "Simulation finished!" << std::endl;

    monitor->CheckForLostPackets();
    monitor->SerializeToXmlFile(flowOutputPath, true, true);

    std::map<FlowId, FlowMonitor::FlowStats> stats = monitor->GetFlowStats();
    for (auto iter = stats.begin(); iter != stats.end(); ++iter)
    {
        std::cout << "Flow ID: " << iter->first << std::endl;
        std::cout << "  Tx Packets: " << iter->second.txPackets << std::endl;
        std::cout << "  Rx Packets: " << iter->second.rxPackets << std::endl;
        std::cout << "  Lost Packets: " << iter->second.lostPackets << std::endl;
        std::cout << "  Throughput: " << iter->second.rxBytes * 8.0 / simulationTime / 1000 << " kbps" << std::endl;
    }

    Simulator::Destroy();
    std::cout << "After Simulator::Run()" << std::endl;

    return 0;
}

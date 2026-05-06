# ISO-Aligned_IoMT-FL-IDS_and_Blockchain_SAF_NS-3

## A Standards-Aligned IoMT Federated Learning and Blockchain Framework for MITM Mitigation and Risk Quantification using NS-3

### Abstract
The increasing reliance on Internet of Medical Things (IoMT) systems introduces critical vulnerabilities to advanced cyber threats such as Man-in-the-Middle (MITM) attacks, which simultaneously compromise data integrity, availability, and clinical safety. This paper presents a standards-aligned security framework integrating a Federated Learning-based Intrusion Detection System (FL-IDS) with blockchain to enable real-time detection, mitigation, and risk quantification of MITM attacks in IoMT networks. The framework is implemented within an NS-3 simulation environment, where MITM attacks are injected and mitigated using distributed, privacy-preserving anomaly detection across heterogeneous devices. Experimental results reveal that MITM attacks produce selective, high-severity disruptions rather than uniform degradation, with critical flow collapse and hybrid anomaly patterns that evade traditional intrusion detection approaches. To quantify attack impact, derived performance metrics—Throughput Reduction Ratio (TRR), Packet Loss Ratio (PLR), Network Delay Increase (NDI), and Jitter Variation Increase (JVI)—are aggregated into a device-weighted Attack Severity Index (wASI). This enables fine-grained, flow-level assessment of clinically relevant degradation. The framework aligns with ISO/IEEE 11073, ISO 14971, ISO/IEC 27001, ISO/IEC 27005, and IEC 80001-1 standards, achieving 94% concordance across clinical, cybersecurity, and governance risk classifications. The proposed approach bridges the gap between fragmented compliance standards by providing a unified, actionable framework for AI-driven intrusion detection, mitigation, and clinically interpretable risk assessment in IoMT environments.

#### Keywords: 
Blockchain, Federated Learning, Intrusion Detection System, IoMT Security, ISO 11073, MITM Attack, NS-3, Risk Assessment.

## Introduction
The rapid adoption of Internet of Medical Things (IoMT) systems has enabled real-time patient monitoring, remote diagnostics, and automated therapeutic interventions. However, this increased interconnectivity exposes IoMT networks to sophisticated cyber threats, particularly Man-in-the-Middle (MITM) attacks, which can simultaneously compromise data integrity, availability, and clinical safety.
Traditional intrusion detection systems (IDS) are limited in their ability to detect hybrid anomaly patterns, where simultaneous degradation occurs across multiple network metrics such as throughput, packet delivery, delay, and jitter. Blockchain-based approaches enhance data integrity and auditability but offer a fundamentally limited security perimeter: they protect data at rest and provide tamper-resistant audit trails, yet they do not secure data in transit and introduce resource latency and computational overhead that can impair real-time IoMT communication. These limitations necessitate complementary mechanisms—specifically, AI-driven intrusion detection capable of real-time threat response. While various international standards exist to address medical device safety, cybersecurity, and network governance, they are typically applied in isolation, failing to provide holistic, context-aware assurance for IoMT ecosystems.
This reveals a critical research gap: the absence of a unified, standards-aligned framework that enables context-aware, real-time intrusion detection, mitigation, and clinically interpretable risk quantification in IoMT environments. To address this gap, this paper proposes a standards-aligned security framework integrating a Federated Learning-based Intrusion Detection System (FL-IDS) with blockchain. A key contribution is the introduction of a device-weighted Attack Severity Index (wASI), derived from multi-metric degradation indicators and grounded in ISO/IEEE 11073 clinical thresholds, mapped to ISO 14971, ISO/IEC 27001, ISO/IEC 27005, and IEC 80001-1.

## Main Contributions
1.	A wASI grounded in ISO/IEEE 11073-defined clinical thresholds, enabling quantitative and clinically interpretable assessment of IoMT network disruptions.
2.	A governance framework integrating ISO 14971, ISO/IEC 27001, ISO/IEC 27005, and IEC 80001-1, providing a unified mapping between cybersecurity events and clinical risk classifications.
3.	A flow-level vulnerability taxonomy identifying infrastructure, throughput-dependent, timing-critical, and cryptographic weaknesses, enabling targeted and standards-aligned mitigation strategies.
4.	A distributed FL-IDS capable of detecting hybrid, multi-metric anomalies in IoMT environments without centralising sensitive medical data.
5.	A blockchain-enabled audit layer ensuring integrity, traceability, and compliance of detection and mitigation processes via SHA-256 hashing, RSA-2048 digital signatures, and AES-256-CBC encryption.

## System Architecture
The proposed architecture models a heterogeneous IoMT environment comprising medical devices (including a Baxter Wireless Infusion Pump (WIP) and a Hexoskin Smart Health System (SHS)), communication infrastructure, and backend services (shown in Figure 1). 

<img width="1028" height="531" alt="image" src="https://github.com/user-attachments/assets/8bcad3d0-8773-4234-ac03-27b5e4127c6c" />

#### Figure 1: IoMT network architecture with MITM attack vector, FL-IDS detection layer, and blockchain audit logging (RM Rajab et al., 2025).

The WIP is throughput-critical—concerned primarily with reliable delivery of infusion commands—while the SHS is timing-critical, requiring consistent packet inter-arrival intervals for accurate physiological monitoring.

Communication is supported via a hybrid Wi-Fi (IEEE 802.11) and Bluetooth P2P framework. Data is transmitted through an access point (AP) to an edge node (MQTT publisher) and subsequently to a cloud-based Electronic Medical Record (EMR) system. A MITM attacker node is introduced within the NS-3 environment to intercept and manipulate traffic, primarily targeting WIP flows. The architecture integrates a distributed FL-IDS for real-time anomaly detection and a blockchain layer for secure, tamper-resistant logging of events and mitigation actions.

## Methodology
### Simulation Setup
The NS-3 simulation models eighteen communication flows across the two target IoMT devices using Wi-Fi and Bluetooth protocols. Application-layer traffic is generated using MQTT-based OnOff communication. Table I in the main conference paper summarises the key simulation parameters. The ISO/IEEE 11073 severity thresholds and device-specific wASI weights are encoded directly as constants in the simulation, ensuring implementation fidelity to the standards framework.

### MITM Attack Model
The MITM attacker performs selective packet interception, delay injection, and throughput degradation, producing hybrid anomalies across multiple performance metrics simultaneously. The attack targets the Wi-Fi communication channel primarily servicing the WIP, while affecting SHS Bluetooth-bridged flows through shared infrastructure. The selective nature of the attack—prioritising high-value medical data streams—results in a bimodal severity distribution across flows rather than uniform degradation.

### Derived Metrics and wASI
Attack impact is quantified using four derived metrics computed from NS-3 FlowMonitor XML output. 

•	The Throughput Reduction Ratio (TRR) measures the percentage decrease in network throughput due to the attack:
TRR = (T_normal - T_attack) / T_normal × 100   (1)

•	The Packet Loss Ratio (PLR) is derived from the Packet Delivery Ratio (PDR):
PDR = (P_received / P_sent) × 100,    PLR = 100 - PDR   (2)

•	The Network Delay Increase (NDI) measures the percentage increase in one-way delay (OWD) relative to baseline, aligned with ITU-T Y.1541:

NDI = (D_attack - D_normal) / D_normal × 100   (3)

•	The Jitter Variation Increase (JVI) quantifies the normalised change in packet delay variation (PDV):
JVI = |J_attack - J_normal| / J_normal × 100   (4)

An unweighted Attack Severity Index (ASI) aggregates the four metrics:
ASI = (TRR + PLR + NDI + JVI) / 4   (5)

To reflect the distinct clinical priorities of each device—derived from ISO/IEEE 11073 performance tolerances—a device-weighted wASI is applied. For the WIP, throughput and packet delivery are availability-critical (infusion command delivery); for the SHS, delay and jitter are integrity-critical (physiological signal fidelity):

wASI_WIP = (0.4 × TRR) + (0.3 × PLR) + (0.2 × NDI) + (0.1 × JVI)   (6)
wASI_SHS = (0.2 × TRR) + (0.2 × PLR) + (0.3 × NDI) + (0.3 × JVI)   (7)

All metric computations were validated through manual recalculation of 10% of flows (100% concordance), boundary testing, internal consistency checks (PLR + PDR ≈ 100%), and baseline validation against NS-3 reference performance and ISO/IEEE 11073 clinical thresholds. Table II summarises each of the derived metrics and its device-specific sensitivity.

### FL-IDS Detection and Mitigation
Each IoMT device node maintains a FederatedModel instance that tracks a rolling history of local packet loss observations (up to 1000 samples). A NodeMonitor struct encapsulates the per-node detection logic. The FL-IDS detection cycle operates as follows:
1.	Each IoMT node monitors local traffic metrics (TRR, PLR, NDI, JVI) via FlowMonitor.
2.	Lost packets are buffered per flow for forensic analysis and potential retransmission.
3.	Nodes periodically share local loss rates; a global average is computed via federated aggregation.
4.	Anomaly detection fires when a node's local loss rate exceeds the global average by a configurable threshold (default: 0.15).
5.	Attack prediction classifies flows as benign or malicious (loss threshold: 0.1); severity is mapped to ISO 11073 bands (NONE/LOW/MEDIUM/HIGH).
6.	Mitigation is triggered: the MITM attacker node is disabled and affected flows are re-routed with packet retransmission via the DetectAndRecoverMITM function.
7.	All events, wASI values, and mitigation actions are logged immutably to the blockchain layer.

An OptimizedQoSBuffer class provides adaptive jitter control, dynamically adjusting buffer parameters based on FL-IDS-detected severity levels and enforcing per-flow burst limits to stabilise Packet Delay Variation (PDV) under adversarial conditions. Flow IDs 1–5 are assigned stricter timing constraints; an exponential moving average smooths PDV for critical flows.

### Blockchain Integration
The blockchain layer provides tamper-resistant logging of all security events. Each block contains: a previousHash linking to the prior block (ensuring chain immutability); a UNIX timestamp; an AES-256-CBC encrypted data payload; a SHA-256 hash of the concatenated block contents; and an RSA-2048 digital signature for non-repudiation. The Blockchain class initialises with a Genesis Block and adds new blocks on each security event. Any modification to any block—even a single bit—invalidates the entire chain, making tampering detectable. The blockchain does not mitigate active attacks—it protects data at rest and audit trails only, leaving data-in-transit security to the FL-IDS and TLS/SSL layer. This complementary division of responsibility is a deliberate architectural choice grounded in the limitations of blockchain in real-time adversarial contexts.

### Standards Alignment and Risk Classification
wASI values are classified against ISO/IEEE 11073 clinical thresholds (None: ±10%; Low: 10–25%; Medium: 25–50%; High: 50–75%; Critical: >75%) and mapped to ISO/IEC 27005 risk levels and ISO 14971 action levels. CIA triad scores (Confidentiality, Integrity, Availability) are computed with weights C=0.33, I=0.33, A=0.34, emphasising availability given its clinical primacy in IoMT operation. ISO 14971 device criticality factors (WIP=1.00, SHS=0.85) modulate priority scores against device-specific action thresholds (WIP: 50/70/90; SHS: 55/70/85), ensuring that identical ASI values yield higher-priority action levels for the WIP than the SHS, consistent with their respective clinical roles.

## Discussion
The results confirm that IoMT security requires multi-dimensional, flow-aware detection mechanisms capable of capturing hybrid anomaly patterns. Traditional single-metric IDS approaches are inadequate for detecting selective and concurrent metric deviations, particularly in heterogeneous medical environments where device-specific clinical thresholds differ.
The integration of FL-IDS and blockchain provides a complementary security architecture addressing distinct threat surfaces. FL-IDS delivers real-time, privacy-preserving anomaly detection without centralising sensitive medical data; blockchain delivers post-hoc integrity assurance and auditability. The architectural separation is deliberate: blockchain alone cannot mitigate active MITM attacks as it does not protect data in transit, and FL-IDS without secure logging is vulnerable to evidence tampering. Together they form a defence-in-depth model aligned with IEC 80001-1 governance pillars.
The flow-level vulnerability taxonomy reveals that a single systemic cryptographic gap—the absence of mutual authentication and encryption across all flows—was the root enabler of MITM exploitation. This finding supports the recommendation to implement TLS/SSL with mutual authentication as a foundational control, with FL-IDS and blockchain operating as compensating and monitoring layers. The asymmetric alarm behaviour between WIP and SHS (WIP triggers immediate alarms; SHS may fail silently) is a particularly significant clinical finding with direct implications for IoMT alarm management policies.

 ## Conclusion
These findings presented a standards-aligned framework integrating FL-IDS and blockchain to enhance IoMT security against MITM attacks. The proposed wASI enables quantitative, flow-aware assessment of attack impact, while alignment with ISO/IEEE 11073, ISO 14971, ISO/IEC 27001/27005, and IEC 80001-1 provides clinically interpretable and governance-compliant risk classification.
Experimental results demonstrated that MITM attacks produce selective, high-severity disruptions—including complete flow collapse (wASI = 100%) in critical flows—which are effectively detected and partially mitigated by the proposed FL-IDS framework. The 94% cross-standard concordance validates the coherence of the unified risk model. Statistical validation across ten simulation seeds confirmed significant throughput improvements (p = 0.0039) and packet loss reductions (p < 0.0001). The flow-level vulnerability taxonomy and ISO 14971 priority scoring provide actionable, device-aware guidance for IoMT security governance, addressing a critical gap in existing fragmented compliance approaches.
Limitations have shown a reliance on threshold-based detection (susceptible to adaptive adversaries), simulation-based evaluation (which cannot fully capture hardware failures or electromagnetic interference), and a fixed wASI weighting scheme warranting future sensitivity analysis. Future work could explore fuzzy logic and adaptive scoring models, real-world clinical testbed validation, and extension to additional attack vectors.


# Threat model – `security/` directory

This directory breaks out [`Security.md`](./Security.md): one folder per threat
scenario, each containing a `README.md` describing it. The source document
remains the reference; these sheets make it possible to attach risk notes and
traceability threat by threat. Each sheet associates the scenario with the MITRE
ATT&CK techniques it involves (with their identifier) and one defence measure per
technique.

## Naming convention

`<target>-<category>[-<subcategory>]-<nn>`, where the target is `N` (nodes) or
`C` (clients). The identifiers are stable: do not reuse or renumber them; append
new scenarios at the end.

## Threat index

| ID | Target | Category | Title |
| --- | --- | --- | --- |
| [N-CONF-01](./N-CONF-01/) | Nodes | Confidentiality › Data | Unauthorised reading of stored shards |
| [N-CONF-02](./N-CONF-02/) | Nodes | Confidentiality › Data | Access analysis |
| [N-CONF-03](./N-CONF-03/) | Nodes | Confidentiality › Data | Metadata correlation |
| [N-CONF-04](./N-CONF-04/) | Nodes | Confidentiality › Data | Network traffic observation |
| [N-CONF-05](./N-CONF-05/) | Nodes | Confidentiality › Data | Inference of relationships between users |
| [N-INT-STO-01](./N-INT-STO-01/) | Nodes | Integrity › Storage | Tampering with a shard |
| [N-INT-STO-02](./N-INT-STO-02/) | Nodes | Integrity › Storage | Serving a corrupted shard |
| [N-INT-STO-03](./N-INT-STO-03/) | Nodes | Integrity › Storage | Serving an old version (rollback) |
| [N-INT-STO-04](./N-INT-STO-04/) | Nodes | Integrity › Storage | Local reorganisation of data |
| [N-INT-MET-01](./N-INT-MET-01/) | Nodes | Integrity › Metadata | Metadata falsification |
| [N-INT-MET-02](./N-INT-MET-02/) | Nodes | Integrity › Metadata | Timestamp modification |
| [N-INT-MET-03](./N-INT-MET-03/) | Nodes | Integrity › Metadata | History rewriting |
| [N-INT-MET-04](./N-INT-MET-04/) | Nodes | Integrity › Metadata | Deletion of local events |
| [N-INT-REG-01](./N-INT-REG-01/) | Nodes | Integrity › Registry | Double publication |
| [N-INT-REG-02](./N-INT-REG-02/) | Nodes | Integrity › Registry | Registry rewriting |
| [N-INT-REG-03](./N-INT-REG-03/) | Nodes | Integrity › Registry | Event omission |
| [N-INT-REG-04](./N-INT-REG-04/) | Nodes | Integrity › Registry | Creation of fictitious events |
| [N-INT-REG-05](./N-INT-REG-05/) | Nodes | Integrity › Registry | Event replay |
| [N-INT-PRE-01](./N-INT-PRE-01/) | Nodes | Integrity › Proofs | Fake proofs of storage |
| [N-INT-PRE-02](./N-INT-PRE-02/) | Nodes | Integrity › Proofs | Reuse of old proofs |
| [N-INT-PRE-03](./N-INT-PRE-03/) | Nodes | Integrity › Proofs | Proof mutualisation |
| [N-INT-PRE-04](./N-INT-PRE-04/) | Nodes | Integrity › Proofs | Fabrication of proofs without data |
| [N-INT-PRE-05](./N-INT-PRE-05/) | Nodes | Integrity › Proofs | Falsification of availability proofs |
| [N-INT-ID-01](./N-INT-ID-01/) | Nodes | Integrity › Identity | Identity spoofing |
| [N-INT-ID-02](./N-INT-ID-02/) | Nodes | Integrity › Identity | Identity duplication |
| [N-INT-ID-03](./N-INT-ID-03/) | Nodes | Integrity › Identity | Private key theft |
| [N-DISP-01](./N-DISP-01/) | Nodes | Availability | Deleting a shard |
| [N-DISP-02](./N-DISP-02/) | Nodes | Availability | Refusing to serve a shard |
| [N-DISP-03](./N-DISP-03/) | Nodes | Availability | Refusing to respond |
| [N-DISP-04](./N-DISP-04/) | Nodes | Availability | Deliberate slowdown |
| [N-DISP-05](./N-DISP-05/) | Nodes | Availability | Network partition |
| [N-DISP-06](./N-DISP-06/) | Nodes | Availability | Blocking gossip |
| [N-DISP-07](./N-DISP-07/) | Nodes | Availability | Saturation of CPU, memory, disk or bandwidth |
| [N-DISP-08](./N-DISP-08/) | Nodes | Availability | Refusing maintenance |
| [N-DISP-09](./N-DISP-09/) | Nodes | Availability | Strategic disconnection |
| [N-AC-01](./N-AC-01/) | Nodes | Access control | Ignoring a revocation |
| [N-AC-02](./N-AC-02/) | Nodes | Access control | Granting access without authorisation |
| [N-AC-03](./N-AC-03/) | Nodes | Access control | Serving data after expiry |
| [N-AC-04](./N-AC-04/) | Nodes | Access control | Using stale permissions |
| [N-AC-05](./N-AC-05/) | Nodes | Access control | Falsifying a requester's identity |
| [N-PROTO-01](./N-PROTO-01/) | Nodes | Protocol threats | Injection of fake Gossip messages |
| [N-PROTO-02](./N-PROTO-02/) | Nodes | Protocol threats | Eclipse attack |
| [N-PROTO-03](./N-PROTO-03/) | Nodes | Protocol threats | Redirection to fake peers |
| [N-PROTO-04](./N-PROTO-04/) | Nodes | Protocol threats | Modified software |
| [N-PROTO-05](./N-PROTO-05/) | Nodes | Protocol threats | Exploitation of vulnerabilities |
| [N-PROTO-06](./N-PROTO-06/) | Nodes | Protocol threats | Disabling verifications |
| [N-ECO-01](./N-ECO-01/) | Nodes | Economic threats | Declaring fictitious capacity |
| [N-ECO-02](./N-ECO-02/) | Nodes | Economic threats | Participating only in paid operations |
| [N-ECO-03](./N-ECO-03/) | Nodes | Economic threats | Leaving after reward |
| [N-ECO-04](./N-ECO-04/) | Nodes | Economic threats | Covertly outsourcing storage |
| [N-ORG-SYB-01](./N-ORG-SYB-01/) | Nodes | Organisational threats › Sybil / collusion | Creation of fake nodes |
| [N-ORG-SYB-02](./N-ORG-SYB-02/) | Nodes | Organisational threats › Sybil / collusion | Collusion between nodes |
| [N-ORG-SYB-03](./N-ORG-SYB-03/) | Nodes | Organisational threats › Sybil / collusion | Coordinated censorship |
| [N-ORG-SYB-04](./N-ORG-SYB-04/) | Nodes | Organisational threats › Sybil / collusion | Control of a regional majority |
| [N-ORG-GEO-01](./N-ORG-GEO-01/) | Nodes | Organisational threats › Geolocation | Faking one's location |
| [N-ORG-GEO-02](./N-ORG-GEO-02/) | Nodes | Organisational threats › Geolocation | VPN/proxy |
| [N-ORG-GEO-03](./N-ORG-GEO-03/) | Nodes | Organisational threats › Geolocation | Concentration on the same infrastructure |
| [N-ORG-GEO-04](./N-ORG-GEO-04/) | Nodes | Organisational threats › Geolocation | Fictitious geographic distribution |
| [C-CONF-01](./C-CONF-01/) | Clients | Confidentiality | Inferring the existence of data |
| [C-CONF-02](./C-CONF-02/) | Clients | Confidentiality | Metadata correlation |
| [C-CONF-03](./C-CONF-03/) | Clients | Confidentiality | Observation of response times |
| [C-CONF-04](./C-CONF-04/) | Clients | Confidentiality | Collection of public information |
| [C-INT-DAT-01](./C-INT-DAT-01/) | Clients | Integrity › Data | Sending corrupted data |
| [C-INT-DAT-02](./C-INT-DAT-02/) | Clients | Integrity › Data | Unauthorised modification |
| [C-INT-DAT-03](./C-INT-DAT-03/) | Clients | Integrity › Data | Incompatible versions |
| [C-INT-DAT-04](./C-INT-DAT-04/) | Clients | Integrity › Data | Logical deletion |
| [C-INT-DAT-05](./C-INT-DAT-05/) | Clients | Integrity › Data | Injection of malicious data |
| [C-INT-MET-01](./C-INT-MET-01/) | Clients | Integrity › Metadata | Falsification |
| [C-INT-MET-02](./C-INT-MET-02/) | Clients | Integrity › Metadata | Timestamp modification |
| [C-INT-MET-03](./C-INT-MET-03/) | Clients | Integrity › Metadata | False origin |
| [C-INT-MET-04](./C-INT-MET-04/) | Clients | Integrity › Metadata | Version manipulation |
| [C-INT-MET-05](./C-INT-MET-05/) | Clients | Integrity › Metadata | False recipient list |
| [C-INT-SIG-01](./C-INT-SIG-01/) | Clients | Integrity › Signatures | Double signature |
| [C-INT-SIG-02](./C-INT-SIG-02/) | Clients | Integrity › Signatures | Signing different content |
| [C-INT-SIG-03](./C-INT-SIG-03/) | Clients | Integrity › Signatures | Replay |
| [C-INT-SIG-04](./C-INT-SIG-04/) | Clients | Integrity › Signatures | Stolen signature |
| [C-INT-SIG-05](./C-INT-SIG-05/) | Clients | Integrity › Signatures | Use of a compromised key |
| [C-INT-JRN-01](./C-INT-JRN-01/) | Clients | Integrity › Logs | Preventing an audit |
| [C-INT-JRN-02](./C-INT-JRN-02/) | Clients | Integrity › Logs | Contradictory events |
| [C-INT-JRN-03](./C-INT-JRN-03/) | Clients | Integrity › Logs | Massive noise |
| [C-INT-JRN-04](./C-INT-JRN-04/) | Clients | Integrity › Logs | Re-emission of events |
| [C-DISP-01](./C-DISP-01/) | Clients | Availability | Flood |
| [C-DISP-02](./C-DISP-02/) | Clients | Availability | Multiplying connections |
| [C-DISP-03](./C-DISP-03/) | Clients | Availability | Interrupted downloads |
| [C-DISP-04](./C-DISP-04/) | Clients | Availability | Massive reconstruction requests |
| [C-DISP-05](./C-DISP-05/) | Clients | Availability | Saturation of verifications |
| [C-AC-01](./C-AC-01/) | Clients | Access control | Access without authorisation |
| [C-AC-02](./C-AC-02/) | Clients | Access control | Reuse of an expired right |
| [C-AC-03](./C-AC-03/) | Clients | Access control | Forged token |
| [C-AC-04](./C-AC-04/) | Clients | Access control | Privilege escalation |
| [C-AC-05](./C-AC-05/) | Clients | Access control | Circumventing a revocation |
| [C-AC-06](./C-AC-06/) | Clients | Access control | Sharing rights |
| [C-PROTO-01](./C-PROTO-01/) | Clients | Protocol threats | Non-compliance with the protocol |
| [C-PROTO-02](./C-PROTO-02/) | Clients | Protocol threats | Messages in an invalid order |
| [C-PROTO-03](./C-PROTO-03/) | Clients | Protocol threats | Old version of the protocol |
| [C-PROTO-04](./C-PROTO-04/) | Clients | Protocol threats | Exploitation of undefined behaviours |
| [C-PROTO-05](./C-PROTO-05/) | Clients | Protocol threats | False declaration of capabilities |
| [C-ECO-01](./C-ECO-01/) | Clients | Economic threats | Massive data creation |
| [C-ECO-02](./C-ECO-02/) | Clients | Economic threats | Multiplying operations |
| [C-ECO-03](./C-ECO-03/) | Clients | Economic threats | Repeated creation/deletion |
| [C-ECO-04](./C-ECO-04/) | Clients | Economic threats | Attempting to obtain resources for free |
| [C-COL-01](./C-COL-01/) | Clients | Collusion | Collusion between clients |
| [C-COL-02](./C-COL-02/) | Clients | Collusion | Collusion with nodes |
| [C-COL-03](./C-COL-03/) | Clients | Collusion | Key sharing |
| [C-COL-04](./C-COL-04/) | Clients | Collusion | Coordinated creation of fake events |

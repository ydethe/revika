
# Security Threat Model – Revika
## Purpose
This document catalogues the main attack scenarios against Revika in order to feed the risk analyses. The associated defence measures are detailed, MITRE ATT&CK technique by technique, in the sheets of the [`security/`](./README.md) directory.

Each scenario carries a unique identifier. Convention: `<target>-<category>[-<subcategory>]-<nn>`, where the target is `N` (nodes) or `C` (clients). These identifiers are stable: do not reuse or renumber them, append new scenarios at the end.

## Assets to protect
- Data (shards)
- Metadata
- Access rights
- Distributed log
- Cryptographic identities
- Network availability
- Node location
- Proofs of storage

# Threats targeting nodes

## Confidentiality
### Data
- **N-CONF-01** — Unauthorised reading of stored shards.
- **N-CONF-02** — Access analysis.
- **N-CONF-03** — Metadata correlation.
- **N-CONF-04** — Network traffic observation.
- **N-CONF-05** — Inference of relationships between users.

## Integrity
### Storage
- **N-INT-STO-01** — Tampering with a shard.
- **N-INT-STO-02** — Serving a corrupted shard.
- **N-INT-STO-03** — Serving an old version (rollback).
- **N-INT-STO-04** — Local reorganisation of data.
### Metadata
- **N-INT-MET-01** — Metadata falsification.
- **N-INT-MET-02** — Timestamp modification.
- **N-INT-MET-03** — History rewriting.
- **N-INT-MET-04** — Deletion of local events.
### Registry
- **N-INT-REG-01** — Double publication.
- **N-INT-REG-02** — Registry rewriting.
- **N-INT-REG-03** — Event omission.
- **N-INT-REG-04** — Creation of fictitious events.
- **N-INT-REG-05** — Event replay.
### Proofs
- **N-INT-PRE-01** — Fake proofs of storage.
- **N-INT-PRE-02** — Reuse of old proofs.
- **N-INT-PRE-03** — Proof mutualisation.
- **N-INT-PRE-04** — Fabrication of proofs without data.
- **N-INT-PRE-05** — Falsification of availability proofs.
### Identity
- **N-INT-ID-01** — Identity spoofing.
- **N-INT-ID-02** — Identity duplication.
- **N-INT-ID-03** — Private key theft.

## Availability
- **N-DISP-01** — Deleting a shard.
- **N-DISP-02** — Refusing to serve a shard.
- **N-DISP-03** — Refusing to respond.
- **N-DISP-04** — Deliberate slowdown.
- **N-DISP-05** — Network partition.
- **N-DISP-06** — Blocking gossip.
- **N-DISP-07** — Saturation of CPU, memory, disk or bandwidth.
- **N-DISP-08** — Refusing maintenance.
- **N-DISP-09** — Strategic disconnection.

## Access control
- **N-AC-01** — Ignoring a revocation.
- **N-AC-02** — Granting access without authorisation.
- **N-AC-03** — Serving data after expiry.
- **N-AC-04** — Using stale permissions.
- **N-AC-05** — Falsifying a requester's identity.

## Protocol threats
- **N-PROTO-01** — Injection of fake Gossip messages.
- **N-PROTO-02** — Eclipse attack.
- **N-PROTO-03** — Redirection to fake peers.
- **N-PROTO-04** — Modified software.
- **N-PROTO-05** — Exploitation of vulnerabilities.
- **N-PROTO-06** — Disabling verifications.

## Economic threats
- **N-ECO-01** — Declaring fictitious capacity.
- **N-ECO-02** — Participating only in paid operations.
- **N-ECO-03** — Leaving after reward.
- **N-ECO-04** — Covertly outsourcing storage.

## Organisational threats
### Sybil / collusion
- **N-ORG-SYB-01** — Creation of fake nodes.
- **N-ORG-SYB-02** — Collusion between nodes.
- **N-ORG-SYB-03** — Coordinated censorship.
- **N-ORG-SYB-04** — Control of a regional majority.
### Geolocation
- **N-ORG-GEO-01** — Faking one's location.
- **N-ORG-GEO-02** — VPN/proxy.
- **N-ORG-GEO-03** — Concentration on the same infrastructure.
- **N-ORG-GEO-04** — Fictitious geographic distribution.

# Threats targeting clients

## Confidentiality
- **C-CONF-01** — Inferring the existence of data.
- **C-CONF-02** — Metadata correlation.
- **C-CONF-03** — Observation of response times.
- **C-CONF-04** — Collection of public information.

## Integrity
### Data
- **C-INT-DAT-01** — Sending corrupted data.
- **C-INT-DAT-02** — Unauthorised modification.
- **C-INT-DAT-03** — Incompatible versions.
- **C-INT-DAT-04** — Logical deletion.
- **C-INT-DAT-05** — Injection of malicious data.
### Metadata
- **C-INT-MET-01** — Falsification.
- **C-INT-MET-02** — Timestamp modification.
- **C-INT-MET-03** — False origin.
- **C-INT-MET-04** — Version manipulation.
- **C-INT-MET-05** — False recipient list.
### Signatures
- **C-INT-SIG-01** — Double signature.
- **C-INT-SIG-02** — Signing different content.
- **C-INT-SIG-03** — Replay.
- **C-INT-SIG-04** — Stolen signature.
- **C-INT-SIG-05** — Use of a compromised key.
### Logs
- **C-INT-JRN-01** — Preventing an audit.
- **C-INT-JRN-02** — Contradictory events.
- **C-INT-JRN-03** — Massive noise.
- **C-INT-JRN-04** — Re-emission of events.

## Availability
- **C-DISP-01** — Flood.
- **C-DISP-02** — Multiplying connections.
- **C-DISP-03** — Interrupted downloads.
- **C-DISP-04** — Massive reconstruction requests.
- **C-DISP-05** — Saturation of verifications.

## Access control
- **C-AC-01** — Access without authorisation.
- **C-AC-02** — Reuse of an expired right.
- **C-AC-03** — Forged token.
- **C-AC-04** — Privilege escalation.
- **C-AC-05** — Circumventing a revocation.
- **C-AC-06** — Sharing rights.

## Protocol threats
- **C-PROTO-01** — Non-compliance with the protocol.
- **C-PROTO-02** — Messages in an invalid order.
- **C-PROTO-03** — Old version of the protocol.
- **C-PROTO-04** — Exploitation of undefined behaviours.
- **C-PROTO-05** — False declaration of capabilities.

## Economic threats
- **C-ECO-01** — Massive data creation.
- **C-ECO-02** — Multiplying operations.
- **C-ECO-03** — Repeated creation/deletion.
- **C-ECO-04** — Attempting to obtain resources for free.

## Collusion
- **C-COL-01** — Collusion between clients.
- **C-COL-02** — Collusion with nodes.
- **C-COL-03** — Key sharing.
- **C-COL-04** — Coordinated creation of fake events.

# revika — B2B Sales Pitch

Sovereignty and resilience, first. Every commercial claim below maps to a real
technical property of revika (client-side encryption, blind nodes, erasure
coding + repair, post-quantum crypto) — so it holds up under scrutiny, which is
what closes B2B deals.

## 1. The hook (30 seconds)

> **"With SharePoint or Google Workspace, your files are encrypted — but Microsoft
> or Google holds the keys. With revika, no one but you can read your data. Not us,
> not the host, not a subcontractor, not a foreign government. Technically
> impossible, not just contractually forbidden."**

The winning angle for sovereignty-minded B2B buyers: the gap between *"we promise
not to look"* (the US cloud model) and *"we cannot look"* (revika). This is the
pivot of the entire conversation from "Software as a Service" to **"Infrastructure as a Property."**

## 2. The four differentiators

### Sovereignty — immunity to de-platforming & geo-politics

- **Client-side encryption**: data leaves your machine already encrypted. Servers
  only ever see illegible fragments addressed by content hash.
- **Zero-knowledge by design**: a node never holds a whole file nor any key.
  Confidentiality does not rest on an operator's promise.
- **Strategic Independence**: For enterprises in sensitive sectors, the risk of being 
  locked out of a SaaS tenant due to policy changes or international sanctions is a 
  existential risk. Revika’s P2P nature ensures data access as long as your nodes exist.
- **Regulatory angle**: de facto immunity to the **CLOUD Act / FISA** — a subpoena
  served on the host returns only unusable ciphertext. Position this against GDPR,
  NIS2, DORA, and SecNumCloud requirements.

### Resilience — the data survives failure

- **Erasure coding** (k=4 data + m=2 parity shards): any 4 of 6 shards rebuild the
  file. Two nodes can go down with no data loss.
- **Automatic repair**: the system continuously regenerates lost shards — on
  ciphertext, without ever decrypting.
- **No single point of failure**: a distributed P2P network, unlike the single
  datacenter a SharePoint tenant depends on.

### Efficiency — turning idle CAPEX into "Internal Cloud"

- **Edge Computing & LAN speeds**: utilize idle storage on branch office servers or 
  workstations as nodes. This turns internal infrastructure into a resilient, 
  high-speed storage mesh that doesn't saturate the WAN like centralized SaaS.
- **Zero-trust by default**: nodes are "blind," so you can use even untrusted or 
  lower-security hardware for storage without risking data confidentiality.

### Longevity — post-quantum cryptography

- **PQC today** (ML-KEM-768, AES-256): protection against *harvest now, decrypt
  later* — the adversary who captures ciphertext today to decrypt it with a future
  quantum computer. Consumer-grade competitors are not there yet.

## 3. Why not them

| | SharePoint / Google Workspace | **revika** |
|---|---|---|
| Who holds the keys | The vendor | **You alone** |
| Vendor cleartext access | Technically possible | **Impossible by design** |
| CLOUD Act exposure | Yes | **No** (client-side encryption) |
| Quantum resistance | No | **Yes (ML-KEM)** |
| Data loss on outage | Depends on SLA | **Algorithmic reconstruction** |
| Ownership | Rented (SaaS) | **Owned (Property)** |
| Infrastructure | Centralized | **Distributed/P2P** |
| Sharing | Copy + vendor-managed rights | **Key sharing** — never a cleartext copy |

## 4. Ease of use — defusing "sovereign means complicated"

This is the number-one objection in B2B. Address it head-on:

> **"Sovereignty without the friction. Spin up a workspace with one command, and
> everyday use stays drag-and-drop."**

- Familiar **scp-like workflow**: `cp file rvk:docs/`.
- **A single `connect`** provisions the workspace: it fetches the network policy,
  generates the keys, and is write-ready. The operator retypes nothing.
- **Multi-device with no conflicts**: automatic three-way reconciliation, never a
  silent lost update.
- **Sharing and revocation in one command**; revocation genuinely re-keys the
  subtree.
- OS filesystem integration on the roadmap (macOS File Provider / Windows Cloud
  Filter / Linux GVfs) → **the familiar network drive** for the end user.

## 5. Commercial Roadmap & Evolutions

To bridge the gap between P2P tool and Enterprise Suite, revika is evolving along these axes:

- **Identity & IAM Integration**: Bridging Corporate Identity (Active Directory/Okta) 
  to revika keys for automated on/offboarding.
- **Cryptographic Audit Trails**: User-signed, immutable access logs published to the 
  DHT to prove compliance (GDPR/HIPAA) without revealing content.
- **Collaboration Primitives**: Real-time collaborative editing using CRDTs (Conflict-free 
  Replicated Data Types) integrated into the manifest layer.
- **Geographic Pinning**: The ability to mandate data residency (e.g., "Germany only") 
  at the shard placement level for legal compliance.
- **Managed Node Marketplace**: A hybrid model mixing private nodes with "Professional 
  Nodes" for 99.99% availability guarantees.

## 6. Closing by target

- **Sectors to target**: defense, healthcare, legal, R&D, public sector, finance —
  those for whom a leak is existential and compliance is binding.
- **Call to action**: *"We install a node at your site this week. You drop a file,
  you kill two servers, and it's still there — and unreadable everywhere else."* →
  the demo that beats a thousand slides.

## Honesty guardrails (credibility = not overselling)

- The product is **in development** (PoC of the core encryption / erasure / repair
  loop). Position it to your prospect's maturity — *design partner / pilot*, not
  "turnkey enterprise production".
- **Revocation** protects future reads, not copies already downloaded — say so
  plainly; it builds trust.

# Contrôles de défense — inventaire consolidé (D3FEND + NIST 800-53)

Liste unique des techniques **MITRE D3FEND** et contrôles **NIST SP 800-53 Rev 5** référencés dans les tables `## Correspondance cadres de défense` des fiches `security/<ID>/README.md`. Le nombre d'occurrences compte chaque apparition d'un identifiant dans une cellule `D3FEND` ou `NIST 800-53` de ces tables (une cellule listant plusieurs IDs compte pour chacun). Descriptions issues des référentiels officiels (voir aussi [frameworks.md](frameworks.md)). Table triée par nombre d'occurrences décroissant, puis par pertinence (*Mise en œuvre* avant *Code*).

La colonne **Pertinence revika** distingue :

- **Code** — mesure réalisée *dans le code* de revika : c'est l'une des primitives de défense implémentées en propre (table maîtresse P1–P27 de [frameworks.md](frameworks.md)) — chiffrement AEAD, encapsulation ML-KEM, signatures Ed25519, hachage de contenu, erasure coding/réparation, rate-limiting/gater, validation de protocole, ledger/quotas, etc.

- **Mise en œuvre** — mesure relevant du *déploiement / de l'exploitation* d'un nœud ou d'un poste (durcissement OS, monitoring, filtrage réseau périmétrique, sauvegardes hors site, gestion de comptes, processus de développement…), hors périmètre du code revika. Ces IDs proviennent des mappings ATT&CK→contrôles agrégés (CTID / D3FEND via neo4j) et constituent la défense en profondeur à la charge de l'opérateur.

- Fiches analysées : **105**
- Techniques D3FEND uniques : **23** — occurrences totales : **1153**
- Contrôles NIST 800-53 uniques : **96** — occurrences totales : **2786**
- Pertinence : **26** contrôles *Code* / **93** contrôles *Mise en œuvre*

| Framework | ID | Description | Nombre d'occurrences | Pertinence revika |
| --- | --- | --- | --- | --- |
| NIST SP 800-53 Rev 5 | CM-6 | Configuration Settings | 158 | Mise en œuvre |
| MITRE D3FEND | D3-OSM | Operating System Monitoring | 150 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-4 | System Monitoring | 150 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-3 | Access Enforcement | 138 | Code |
| MITRE D3FEND | D3-EAL | Executable Allowlisting | 136 | Mise en œuvre |
| MITRE D3FEND | D3-EDL | Executable Denylisting | 136 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-7 | Software, Firmware, and Information Integrity | 130 | Code |
| NIST SP 800-53 Rev 5 | CA-7 | Continuous Monitoring | 111 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-2 | Baseline Configuration | 106 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-7 | Least Functionality | 103 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-7 | Boundary Protection | 94 | Code |
| NIST SP 800-53 Rev 5 | SC-36 | Distributed Processing and Storage | 91 | Code |
| NIST SP 800-53 Rev 5 | AC-6 | Least Privilege | 88 | Mise en œuvre |
| MITRE D3FEND | D3-LFP | Local File Permissions | 88 | Mise en œuvre |
| MITRE D3FEND | D3-UAP | User Account Permissions | 88 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-2 | Account Management | 76 | Mise en œuvre |
| MITRE D3FEND | D3-NTA | Network Traffic Analysis | 74 | Mise en œuvre |
| MITRE D3FEND | D3-ITF | Inbound Traffic Filtering | 74 | Code |
| NIST SP 800-53 Rev 5 | AC-16 | Security and Privacy Attributes | 66 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-17 | Remote Access | 63 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-4 | Information Flow Enforcement | 63 | Mise en œuvre |
| MITRE D3FEND | D3-OTF | Outbound Traffic Filtering | 63 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-12 | Information Management and Retention | 62 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-19 | Access Control for Mobile Devices | 57 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-20 | Use of External Systems | 57 | Mise en œuvre |
| MITRE D3FEND | D3-FA | File Analysis | 54 | Mise en œuvre |
| MITRE D3FEND | D3-PA | Process Analysis | 54 | Mise en œuvre |
| MITRE D3FEND | D3-PM | Platform Monitoring | 54 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-3 | Malicious Code Protection | 54 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-8 | System Component Inventory | 52 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-18 | Wireless Access | 51 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-2 | Identification and Authentication (organizational Users) | 51 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-28 | Protection of Information at Rest | 51 | Code |
| NIST SP 800-53 Rev 5 | SC-4 | Information in Shared System Resources | 51 | Code |
| NIST SP 800-53 Rev 5 | CP-9 | System Backup | 46 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-5 | Separation of Duties | 44 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CP-7 | Alternate Processing Site | 44 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-5 | Denial-of-service Protection | 41 | Code |
| MITRE D3FEND | D3-LAM | Local Account Monitoring | 39 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-5 | Access Restrictions for Change | 37 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-15 | Information Output Filtering | 37 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CP-10 | System Recovery and Reconstitution | 35 | Code |
| NIST SP 800-53 Rev 5 | SC-6 | Resource Availability | 33 | Code |
| MITRE D3FEND | D3-FH | File Hashing | 32 | Code |
| MITRE D3FEND | D3-MAN | Message Authentication | 32 | Code |
| NIST SP 800-53 Rev 5 | RA-5 | Vulnerability Monitoring and Scanning | 30 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CP-6 | Alternate Storage Site | 29 | Mise en œuvre |
| MITRE D3FEND | D3-MENCR | Message Encryption | 29 | Code |
| NIST SP 800-53 Rev 5 | IA-5 | Authenticator Management | 24 | Code |
| NIST SP 800-53 Rev 5 | SC-8 | Transmission Confidentiality and Integrity | 22 | Code |
| NIST SP 800-53 Rev 5 | SI-16 | Memory Protection | 21 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-4 | Identifier Management | 20 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-46 | Cross Domain Policy Enforcement | 20 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-9 | Service Identification and Authentication | 19 | Mise en œuvre |
| MITRE D3FEND | D3-NTF | Network Traffic Filtering | 18 | Code |
| NIST SP 800-53 Rev 5 | SC-23 | Session Authenticity | 18 | Code |
| NIST SP 800-53 Rev 5 | AU-10 | Non-repudiation | 17 | Code |
| NIST SP 800-53 Rev 5 | SA-8 | Security and Privacy Engineering Principles | 17 | Code |
| NIST SP 800-53 Rev 5 | AU-9 | Protection of Audit Information | 16 | Code |
| NIST SP 800-53 Rev 5 | CP-2 | Contingency Plan | 15 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-12 | Cryptographic Key Establishment and Management | 15 | Code |
| NIST SP 800-53 Rev 5 | SA-11 | Developer Testing and Evaluation | 13 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SA-15 | Development Process, Standards, and Tools | 13 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-2 | Flaw Remediation | 12 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-11 | User-installed Software | 11 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-37 | Out-of-band Channels | 11 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CA-3 | Information Exchange | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-10 | Software Usage Restrictions | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-12 | Identity Proofing | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SA-10 | Developer Configuration Management | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SA-17 | Developer Security and Privacy Architecture and Design | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SA-3 | System Development Life Cycle | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SA-4 | Acquisition Process | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-43 | Usage Restrictions | 10 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-8 | Identification and Authentication (non-organizational Users) | 8 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-10 | Information Input Validation | 7 | Code |
| NIST SP 800-53 Rev 5 | IA-3 | Device Identification and Authentication | 6 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-18 | Mobile Code | 6 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-7 | Unsuccessful Logon Attempts | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-8 | System Use Notification | 5 | Mise en œuvre |
| MITRE D3FEND | D3-AL | Account Locking | 5 | Mise en œuvre |
| MITRE D3FEND | D3-EI | Execution Isolation | 5 | Mise en œuvre |
| MITRE D3FEND | D3-NI | Network Isolation | 5 | Mise en œuvre |
| MITRE D3FEND | D3-SCP | System Configuration Permissions | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | RA-10 | Threat Hunting | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-2 | Separation of System and User Functionality | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-3 | Security Function Isolation | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-30 | Concealment and Misdirection | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-39 | Process Isolation | 5 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AU-6 | Audit Record Review, Analysis, and Reporting | 5 | Code |
| NIST SP 800-53 Rev 5 | AC-23 | Data Mining Protection | 4 | Mise en œuvre |
| MITRE D3FEND | D3-JFAPA | Job Function Access Pattern Analysis | 4 | Mise en œuvre |
| MITRE D3FEND | D3-RAPA | Resource Access Pattern Analysis | 4 | Mise en œuvre |
| MITRE D3FEND | D3-UDTA | User Data Transfer Analysis | 4 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-6 | Authentication Feedback | 4 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SI-5 | Security Alerts, Advisories, and Directives | 4 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-3 | Configuration Change Control | 3 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-17 | Public Key Infrastructure Certificates | 3 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-29 | Heterogeneity | 3 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | AC-21 | Information Sharing | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CA-2 | Control Assessments | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | CM-12 | Information Location | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-10 | Network Disconnect | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-20 | Secure Name/address Resolution Service (authoritative Source) | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-21 | Secure Name/address Resolution Service (recursive or Caching Resolver) | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-22 | Architecture and Provisioning for Name/address Resolution Service | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-26 | Decoys | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-31 | Covert Channel Analysis | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-35 | External Malicious Code Identification | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-38 | Operations Security | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SR-5 | Acquisition Strategies, Tools, and Methods | 2 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-13 | Cryptographic Protection | 2 | Code |
| NIST SP 800-53 Rev 5 | SR-11 | Component Authenticity | 2 | Code |
| NIST SP 800-53 Rev 5 | SR-4 | Provenance | 2 | Code |
| NIST SP 800-53 Rev 5 | AC-10 | Concurrent Session Control | 1 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | IA-11 | Re-authentication | 1 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SA-22 | Unsupported System Components | 1 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-34 | Non-modifiable Executable Programs | 1 | Mise en œuvre |
| NIST SP 800-53 Rev 5 | SC-44 | Detonation Chambers | 1 | Mise en œuvre |

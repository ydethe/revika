# N-PROTO-05 — Exploitation de vulnérabilités

- **Cible** : Nœuds
- **Catégorie** : Menaces protocolaires
- **Identifiant** : N-PROTO-05

## Description
Un attaquant exploite une faille d'implémentation du nœud pour en détourner le comportement.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Exploitation of Remote Services | T1210 | L'attaquant exploite à distance une faille d'implémentation exposée via les protocoles libp2p du nœud. | Protocoles libp2p versionnés et code pur-Go / cgo-free réduisant la surface d'attaque, avec `ResourceManager` plafonnant les ressources par connexion. |
| Exploitation for Privilege Escalation | T1068 | La faille est mise à profit pour détourner le comportement du nœud au-delà de ses droits normaux. | Cloisonnement des données côté nœud (ciphertext uniquement, aucune clé) : une compromission du process n'expose pas de plaintext ni de capacités. |

## Correspondance cadres de défense

| Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
| --- | --- | --- | --- |
| Protocoles versionnés + fail-closed | T1210 | — | SI-10 |
| ConnectionGater / ResourceManager / ConnManager | T1210 | D3-NTF | SC-7 |
| Nœud « dumb/untrusted » + re-vérification côté User | T1068 | — | SA-8 |
| Contrôles CTID (neo4j) | T1210 | — | AC-2, AC-3, AC-4, AC-5, AC-6, CA-2, CA-7, CM-2, CM-5, CM-6, CM-7, CM-8, IA-2, IA-8, RA-5, RA-10, SC-2, SC-3, SC-18, SC-26, SC-29, SC-30, SC-35, SC-39, SC-46, SI-2, SI-3, SI-4, SI-5, SI-7 |
| Contrôles CTID (neo4j) | T1068 | — | AC-2, AC-4, AC-6, CA-7, CM-2, CM-6, CM-7, CM-8, RA-5, RA-10, SC-2, SC-3, SC-7, SC-18, SC-30, SC-39, SI-2, SI-3, SI-4, SI-5, SI-7 |
| Techniques D3FEND (neo4j) | T1210 | D3-EAL, D3-EDL, D3-EI, D3-FA, D3-ITF, D3-LAM, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |
| Techniques D3FEND (neo4j) | T1068 | D3-EI, D3-FA, D3-ITF, D3-LFP, D3-NI, D3-NTA, D3-OSM, D3-OTF, D3-PA, D3-PM, D3-SCP, D3-UAP | — |

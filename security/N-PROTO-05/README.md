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

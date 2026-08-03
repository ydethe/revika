# C-INT-JRN-01 — Empêcher un audit

- **Cible** : Clients
- **Catégorie** : Intégrité › Journaux
- **Identifiant** : C-INT-JRN-01

## Description
Un acteur empêche la tenue ou la lecture des journaux nécessaires à un audit côté client.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Impair Defenses: Disable or Modify Tools | T1562.001 | L'acteur désactive ou entrave le mécanisme de journalisation nécessaire à l'audit. | Tenir des journaux d'audit append-only signés et chaînés (hash-chain), dont l'arrêt ou la falsification crée une rupture de chaîne détectable. |
| Impair Defenses: Indicator Blocking | T1562.006 | Le flux d'événements d'audit est bloqué pour priver l'auditeur d'indicateurs. | Signer et numéroter séquentiellement les entrées, tout trou de numéro de séquence trahissant un blocage. |
| Indicator Removal: Clear Linux or Mac System Logs | T1070.002 | Les journaux locaux nécessaires à l'audit client sont effacés. | Rendre le journal append-only et chaîné par hash, de sorte qu'une suppression casse la chaîne et soit prouvable. |

# C-INT-JRN-01 — Empêcher un audit

- **Cible** : Clients
- **Catégorie** : Intégrité › Journaux
- **Identifiant** : C-INT-JRN-01

## Description
Un acteur empêche la tenue ou la lecture des journaux nécessaires à un audit côté client.

## Techniques MITRE ATT&CK et défenses

| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Disable or Modify Tools | T1685 | L'acteur désactive ou entrave le mécanisme de journalisation, ou bloque le flux d'événements d'audit, pour priver l'auditeur d'indicateurs. | Journaux d'audit append-only signés et chaînés (hash-chain) avec numérotation séquentielle : arrêt, falsification ou blocage crée une rupture de chaîne ou un trou de numéro de séquence détectable. |
| Disable or Modify Tools: Clear Linux or Mac System Logs | T1685.006 | Les journaux locaux nécessaires à l'audit client sont effacés. | Rendre le journal append-only et chaîné par hash, de sorte qu'une suppression casse la chaîne et soit prouvable. |

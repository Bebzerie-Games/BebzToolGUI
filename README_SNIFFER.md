# Fonctionnalité de Sniffer réseau

L'onglet "Sniffer réseau" permet de capturer et d'analyser le trafic réseau sur vos interfaces réseau, similaire à Wireshark.

## Prérequis

- **Npcap** : Le sniffer utilise la bibliothèque Npcap pour capturer les paquets. Si elle n'est pas installée, un message vous proposera de la télécharger et de l'installer automatiquement.

## Fonctionnalités

### Capture de paquets
- Sélection de l'interface réseau à surveiller
- Démarrage/arrêt de la capture
- Affichage en temps réel des paquets capturés

### Filtrage des paquets
- Filtrage par source
- Filtrage par destination
- Filtrage par protocole
- Effacement de filtres
- Effacement de la liste de paquets

### Analyse de paquets
- Affichage des informations essentielles (heure, source, destination, protocole)
- Informations spécifiques au protocole
- Affichage détaillé du paquet sélectionné
- Représentation hexadécimale des données brutes

### Identification des protocoles
- Identification automatique des protocoles courants :
  - HTTP/HTTPS
  - DNS
  - TCP/UDP
  - ICMP
  - ARP
- Code couleur pour une identification visuelle rapide des protocoles

## Utilisation

1. **Sélectionner une interface** dans la liste déroulante
2. Cliquer sur **Démarrer la capture**
3. Observer les paquets qui apparaissent dans la liste
4. Cliquer sur un paquet pour voir ses détails dans le panneau inférieur
5. Utiliser les filtres pour afficher seulement certains types de paquets
6. Cliquer sur **Arrêter la capture** quand vous avez terminé

## Conseils d'utilisation

- Le filtrage fonctionne sur les paquets déjà capturés et n'affecte pas la capture en cours
- Pour les réseaux très actifs, la capture peut ralentir l'application car de nombreux paquets sont traités
- L'analyse de paquets est limitée au niveau de base et ne decode pas tous les protocoles applicatifs complexes
- En mode promiscuité (activé par défaut), vous pourrez voir les paquets destinés à d'autres machines sur votre réseau

# Projet-toolbox-M1 Toolbox 

Ce projet est une collection d'outils de Pentesting accessibles via une interface graphique. Il suffit de lancer `box.py` pour accéder à toutes les fonctionnalités sans avoir à exécuter les scripts individuellement.


- **Bruteforce SSH** : Tente de se connecter à un serveur SSH en utilisant essayant plusieur mot de passe.
- **Scan de Ports** : Utilise Nmap pour scanner les ports d'une adresse IP.
- **Scan Réseau** : Capture les paquets sur une interface réseau spécifiée.
- **Scan de Vulnérabilités** : Scan une adresse IP à la recherche de vulnérabilités sur les services ouverts.
- **Scan de Fichiers** : Scanne un fichier pour les virus.
- **Génération de Rapport** : Génère un rapport des résultats des différents scans.
-  **Langue** : Il est possible de basculer la langue du français à l'anglais

### Prérequis

Ceci est la configuation minimum recommandé afin de pouvoir démarrer le programme:

1. `Processeur` : Un processeur moderne multicœur est recommandé (Intel Core i5 ou équivalent).
2. `Mémoire` : 8 Go de RAM.
3. `Stockage` : 256 Go d'espace de stockage sur SSD de préférence.
4. `Réseau` : Accès à Internet pour les requêtes API.
5. `Système d'exploitation` : Windows 10/11 (64 bits).

## Installation

Pour exécuter ce projet, vous devez importer les bibliothèques Python suivantes :

1. `nmap` : Pour utiliser Nmap via Python.
2. `re` : Pour les expressions régulières.
3. `os` : Pour les opérations système.
4. `webbrowser` : Pour ouvrir les liens dans un navigateur web.
5. `tkinter` : Pour créer l'interface graphique (généralement inclus avec Python).
6. `paramiko` : Pour les connexions SSH
7. `threading` : Pour la gestion des threads.
8. `socket` : Pour les opérations réseau.
9. `psutil` :  Pour interagir avec les interfaces réseau.
10. `scapy` : Pour la capture de paquets réseau
11. `time` : Pour la gestion du temps.
12. `random` : Pour générer des valeurs aléatoires.
13. `string` : Pour les opérations sur les chaînes de caractères.
14. `PIL` : Pour certaines fonctionnalités graphiques avancées dans tkinter.
15. `requests` : Pour envoyer des requêtes HTTP.
16. `hashlib` : Pour le calcul de hash.

### Installation de Pyhton
Les bibliothèques et modules utilisés dans le script sont compatibles avec Python 3.7 et versions ultérieures.

### Installation des dépendances sur Python
Vous pouvez installer toutes les dépendances en utilisant les commandes `pip` suivantes :

```bash
pip install python-nmap
pip install paramiko
pip install psutil
pip install scapy
pip install pillow
pip install requests
```

### Installation de Nmap
En plus des bibliothèques Python, vous devez également installer Nmap sur votre système. Vous pouvez télécharger et installer Nmap à partir du site officiel de Nmap.

## Utilisation de la toolbox

Pour utiliser la toolbox, il suffit de lancer le fichier "Toolbox.py" :

Cela ouvrira une interface graphique permettant d'accéder à toutes les fonctionnalités décrites ci-dessus.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
### Détails des scripts

Brute Force SSH

Description : Utilise paramiko pour tenter de se connecter à un serveur SSH en utilisant une liste de noms d'utilisateur et de mots de passe.
Utilisation : Permet d'effectuer une attaque par force brute sur un serveur SSH pour trouver des informations d'identification valides.

Scan de Ports

Description : Utilise python-nmap pour intégrer Nmap dans la toolbox et scanner les ports d'une adresse IP ou d'un réseau.
Utilisation : Scanne les ports ouverts sur une cible spécifiée pour identifier les services en cours d'exécution.

Scan réseau

Description : Utilise scapy pour capturer les paquets réseau transitant par une interface réseau sélectionnée.
Utilisation : Surveille le trafic réseau, diagnostique les problèmes de réseau et analyse les communications entre différents hôtes.

Scan de Vulnérabilités

Description : Utilise nmap avec des scripts de détection de vulnérabilités pour scanner les ports et services ouverts sur une cible.
Utilisation : Identifie les vulnérabilités potentielles (CVE) sur les services en cours d'exécution.

Scan de fichiers

Description : Utilise requests pour envoyer des fichiers à VirusTotal et vérifier leur contenu pour détecter des virus.
Utilisation : Sélectionne un fichier local et le scanne pour détecter des virus à l'aide de plusieurs moteurs antivirus.
Génération de rapport PDF

Description : Génère un rapport HTML des résultats des scans et des tests effectués, puis l'ouvre dans un navigateur web.
Utilisation : Compile les résultats des tests et des scans en un rapport facilement consultable.

Sélection de la langue

Description : Interface utilisateur multilingue avec la possibilité de basculer entre l'anglais et le français.
Utilisation : Change la langue de l'interface pour s'adapter aux préférences de l'utilisateur en cliquant sur les drapeaux.

### Ce README fournit une description complète du projet, des fonctionnalités disponibles, des étapes d'installation et des détails d'utilisation pour chaque outil inclus.

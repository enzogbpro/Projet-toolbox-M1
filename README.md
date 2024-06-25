# Projet-toolbox-M1 Toolbox 

Ce projet est une collection d'outils de Pentesting accessibles via une interface graphique. Il suffit de lancer `box.py` pour accéder à toutes les fonctionnalités sans avoir à exécuter les scripts individuellement.

## Fonctionnalités

- **Bruteforce SSH** : Tente de se connecter à un serveur SSH en utilisant une liste de mots de passe, puis des combinaisons basées sur le nom d'utilisateur, puis une série aléatoire allant de 8 à 12 caractères.
- **Scan de Ports** : Utilise Nmap pour scanner les ports d'une adresse IP.
- **Scan Réseau** : Capture les paquets sur une interface réseau spécifiée.
- **Scan de Vulnérabilités** : Scan une adresse IP à la recherche de vulnérabilités sur les services ouverts.
- **Scan de Fichiers** : Scanne un fichier pour les virus en utilisant l'API de VirusTotal.
- **Génération de Rapport PDF** : Génère un rapport PDF des résultats des différents scans.
  
## Installation

Pour exécuter ce projet, vous devez installer les bibliothèques Python suivantes :

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
11. `subprocess` : Pour exécuter des sous-processus.
12. `fpdf` : Pour la génération de rapports PDF.
13. `matplotlib.pyplot` : Pour la génération de graphiques.
14. `time` : Pour la gestion du temps.
15. `random` : Pour générer des valeurs aléatoires.
16. `string` : Pour les opérations sur les chaînes de caractères.
17. `PIL` : Pour certaines fonctionnalités graphiques avancées dans tkinter.
18. `requests` : Pour envoyer des requêtes HTTP.
19. `hashlib` : Pour le calcul de hash.


### Installation des dépendances

Vous pouvez installer toutes les dépendances en utilisant les commandes `pip` suivantes :

```bash
pip install python-nmap
pip install paramiko
pip install psutil
pip install scapy
pip install fpdf
pip install matplotlib
pip install pillow
pip install requests
```
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Installation de Nmap
En plus des bibliothèques Python, vous devez également installer Nmap sur votre système. Vous pouvez télécharger et installer Nmap à partir du site officiel de Nmap.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Fichiers ZIP
allitems.zip : Contient une base de données locale des CVE utilisée par l'outil de recherche de CVE. Il est nécessaire de dézipper ce fichier pour utiliser la fonctionnalité de recherche de CVE.
rockyou.zip : Contient une liste de mots de passe couramment utilisés, utile pour le cracking de mots de passe. Il est nécessaire de dézipper ce fichier pour utiliser la fonctionnalité de cracking de mots de passe.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Instructions pour dézipper allitems.zip et rockyou.zip
Téléchargez les fichiers allitems.zip et rockyou.zip à partir de la source fournie.
Extrayez le contenu des fichiers zip dans le répertoire du projet.
Assurez-vous que les fichiers extraits se trouvent dans le même répertoire que box.py.

Utilisation
Pour utiliser la toolbox, il suffit de lancer le script box.py :
python box.py
Cela ouvrira une interface graphique permettant d'accéder à toutes les fonctionnalités décrites ci-dessus.
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Détails des scripts
Keylogger
Enregistre les frappes de touches et les sauvegarde dans un fichier listkey.txt.

Bruteforce SSH
Utilise paramiko pour tenter de se connecter à un serveur SSH en utilisant une liste de noms d'utilisateur et de mots de passe.

Bruteforce Web Login
Envoie des requêtes HTTP POST à une page de login web pour tenter de se connecter en utilisant une liste de mots de passe.

Scanner ARP
Utilise scapy pour envoyer des requêtes ARP sur une plage d'adresses IP et affiche les périphériques connectés.

Recherche de CVE
Recherche des CVE dans un fichier local allitems.txt et affiche les résultats.

Cracker de mots de passe
Utilise John the Ripper pour cracker des hashes de mots de passe. Les options peuvent être configurées via l'interface graphique.

Scanner de vulnérabilités web
Scanne un site web pour des vulnérabilités courantes comme les injections SQL et le XSS. Utilise requests et beautifulsoup4 pour envoyer des requêtes et analyser les réponses.

Scanner Nmap
Utilise python-nmap pour intégrer Nmap dans la toolbox et scanner les ports d'une adresse IP ou d'un réseau.

Ce README fournit une description complète du projet, des fonctionnalités disponibles, des étapes d'installation et des détails d'utilisation pour chaque outil inclus.

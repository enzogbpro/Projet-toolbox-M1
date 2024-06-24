# Projet-toolbox-M1# Toolbox Pentasting

Ce projet est une collection d'outils de Pentesting accessibles via une interface graphique. Il suffit de lancer `box.py` pour accéder à toutes les fonctionnalités sans avoir à exécuter les scripts individuellement.

## Fonctionnalités

- **Keylogger** : Enregistre les frappes de touches.
- **Bruteforce SSH** : Tente de se connecter à un serveur SSH en utilisant une liste de noms d'utilisateur et de mots de passe.
- **Bruteforce Web Login** : Tente de se connecter à une page de login web en utilisant une liste de mots de passe.
- **Scanner ARP** : Scanne une plage d'adresses IP pour identifier les périphériques connectés au réseau.
- **Recherche de CVE** : Recherche des CVE dans un fichier local.
- **Cracker de mots de passe** : Utilise John the Ripper pour cracker des hashes de mots de passe.
- **Scanner de vulnérabilités web** : Scanne un site web pour des vulnérabilités courantes comme les injections SQL et le XSS.
- **Scanner Nmap** : Utilise Nmap pour scanner les ports d'une adresse IP ou d'un réseau.

## Installation

Pour exécuter ce projet, vous devez installer les bibliothèques Python suivantes :

1. `tkinter` : Pour créer l'interface graphique (généralement inclus avec Python).
2. `pynput` : Pour surveiller les frappes de touches.
3. `requests` : Pour envoyer des requêtes HTTP.
4. `paramiko` : Pour les connexions SSH.
5. `scapy` : Pour envoyer des requêtes ARP.
6. `tqdm` : Pour afficher une barre de progression.
7. `pillow` : Pour certaines fonctionnalités graphiques avancées dans tkinter.
8. `keyboard` : Pour écouter et enregistrer les événements du clavier.
9. `beautifulsoup4` : Pour parser le HTML des pages web.
10. `python-nmap` : Pour utiliser Nmap via Python.

### Installation des dépendances

Vous pouvez installer toutes les dépendances en utilisant les commandes `pip` suivantes :

```bash
pip install pynput
pip install requests
pip install paramiko
pip install scapy
pip install tqdm
pip install pillow
pip install keyboard
pip install beautifulsoup4
pip install python-nmap

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

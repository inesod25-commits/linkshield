# 🛡️ LinkShield

Application web qui vérifie la fiabilité d'un lien avant de l'ouvrir, en s'appuyant sur l'API VirusTotal pour détecter les tentatives de phishing et de malware.

## Fonctionnalités

- **Vérification de lien** : soumission d'une URL et analyse via VirusTotal 
- **Score de risque** : verdict clair (safe / suspect / dangereux) avec code couleur
- **Comptes utilisateurs** : inscription et connexion avec mots de passe hashés (bcrypt)
- **Historique** : chaque vérification est sauvegardée et consultable par utilisateur
- **Interface web** : formulaire simple pour tester sans passer par une API brute

## Stack technique

- **Backend** : Python, Flask, Flask-SQLAlchemy, Flask-Bcrypt, Flask-CORS
- **Base de données** : SQLite
- **API externe** : [VirusTotal](https://www.virustotal.com/)
- **Frontend** : HTML / CSS / JavaScript (vanilla)

## Aperçu

![Aperçu LinkShield](docs/screenshot.png)

## Installation

```bash
git clone https://github.com/inesod25-commits/linkshield.git
cd linkshield
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
```

Crée un fichier `.env` à la racine du projet (voir `.env.example`) avec ta propre clé API VirusTotal :
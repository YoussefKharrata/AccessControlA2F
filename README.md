# Système de Contrôle d'Accès par Badge avec Authentification A2F

![Java](https://img.shields.io/badge/Java-8+-blue)
![JavaCard](https://img.shields.io/badge/JavaCard-3.0.4-green)
![License](https://img.shields.io/badge/license-MIT-blue)

## 📋 Description

Système de contrôle d'accès sécurisé utilisant des cartes à puce JavaCard et une authentification à deux facteurs (A2F). Ce projet combine :
- **Facteur 1** : Code PIN (ce que vous savez)
- **Facteur 2** : Clé privée stockée sur carte (ce que vous possédez)

Développé dans le cadre du projet académique de sécurité des systèmes informatiques.

## ✨ Fonctionnalités

- ✅ Authentification à deux facteurs robuste
- ✅ Chiffrement AES-128-CBC des données sensibles
- ✅ Gestion de sessions avec timeout automatique (5 minutes)
- ✅ Traçabilité complète des accès (logs)
- ✅ Protection contre les attaques par force brute (3 tentatives)
- ✅ Mode démonstration (sans matériel)

## 🏗️ Architecture

┌─────────────┐      APDU       ┌──────────────┐
│  Client     │ ←─────────────→ │ Carte JavaCard│
│  Java       │   (ISO 7816)    │   Applet      │
└─────────────┘                 └──────────────┘
│                               │
│                               │
▼                               ▼
┌─────────────┐                 ┌──────────────┐
│ Gestion     │                 │ Stockage     │
│ - Sessions  │                 │ - PIN        │
│ - Logs      │                 │ - Clé AES    │
│ - UI        │                 │ - Clé privée │
└─────────────┘                 └──────────────┘

## 📦 Structure du Projet
access-control-a2f/
├── javacard/          # Applet JavaCard
├── client/            # Application cliente
├── docs/              # Documentation et rapport
├── scripts/           # Scripts utilitaires
└── eclipse/           # Configuration Eclipse

## 🚀 Installation et Utilisation

### Prérequis

- Java JDK 8 ou supérieur
- JavaCard Development Kit 3.0.4
- Eclipse IDE
- Lecteur de carte à puce (optionnel pour le mode démo)

### Installation

1. **Cloner le repository**
```bash
   git clone https://github.com/votre-username/access-control-a2f.git
   cd access-control-a2f
```

2. **Compiler l'applet JavaCard**
```bash
   cd javacard
   ant build
```

3. **Compiler l'application cliente**
```bash
   cd client
   ant jar
```

### Utilisation

#### Mode Normal (avec carte physique)
```bash
# Installer l'applet sur la carte (avec GPShell)
gpshell < scripts/install-applet.txt

# Exécuter le client
java -jar client/dist/AccessControlClient.jar
```

#### Mode Démonstration (sans carte)
```bash
# Compiler et exécuter le mode démo
cd client/src
javac com/accesscontrol/client/DemoAccessControlClient.java
java com.accesscontrol.client.DemoAccessControlClient
```

## 📖 Documentation

- [Rapport Technique Complet](docs/rapport-technique.pdf)
- [Guide d'Installation Eclipse](eclipse/import-instructions.md)
- [Vidéo Démonstration](docs/video-demo.md)
- [Architecture Détaillée](docs/architecture/)

## 🔒 Sécurité

### Modules Implémentés

1. **Module PIN**
   - Validation sécurisée avec OwnerPIN
   - Maximum 3 tentatives
   - Blocage automatique de la carte

2. **Module de Chiffrement**
   - Algorithme : AES-128-CBC
   - Clé dérivée du PIN
   - Stockage sécurisé sur la carte

3. **Module d'Authentification**
   - Authentification à deux facteurs
   - Validation séquentielle des facteurs
   - Logs détaillés de toutes les tentatives

4. **Module de Gestion de Session**
   - Timeout configurable (5 minutes par défaut)
   - Identifiants uniques (UUID)
   - Fermeture automatique et manuelle

5. **Module de Traçabilité**
   - Logs horodatés
   - Enregistrement de la durée des sessions
   - Persistance dans fichier

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

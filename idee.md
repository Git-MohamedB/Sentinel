Agis en tant qu'Ingénieur DevOps et Expert en Cybersécurité Senior. Mon objectif est de créer un projet de portfolio nommé "Sentinel Réseau". Il s'agit d'un système de détection d'intrusions (IDS) basé sur une IA locale (Ollama) fonctionnant dans un environnement Dockerisé.

Voici le cahier des charges. Merci de générer le code étape par étape en respectant scrupuleusement ces consignes :

# 1. CONTEXTE ET OBJECTIF

Je veux déployer un réseau local virtuel contenant un serveur web vulnérable (Nginx) servant de "Honey Pot" (pot de miel). Un script Python (le Sentinel) doit lire les logs d'accès de Nginx en temps réel, envoyer chaque ligne suspecte à une IA locale (Ollama / Llama 3) pour analyse, et simuler le bannissement de l'IP attaquante si l'IA confirme une menace.

# 2. STACK TECHNIQUE

- Infrastructure : Docker et Docker Compose.
- Serveur Cible : Nginx (image officielle alpine).
- Sentinel (Logique) : Python 3.9+ (image slim).
- IA : Ollama avec le modèle llama3:8b (qui tourne déjà sur l'hôte, hors Docker).

# 3. ARCHITECTURE DES FICHIERS ATTENDUE

Crée l'arborescence suivante :
/sentinel_project
├── docker-compose.yml
├── sentinel/
│ ├── Dockerfile
│ ├── requirements.txt
│ └── sentinel.py
└── logs/ (dossier partagé via volume pour access.log)

# 4. CONSIGNES DE DÉVELOPPEMENT (TRÈS IMPORTANT)

- Robustesse : Le script `sentinel.py` doit inclure une gestion des erreurs propre (ex: si l'API d'Ollama ne répond pas, le script ne doit pas planter).
- Performance : N'envoie pas toutes les requêtes HTTP normales à l'IA. Fais un premier filtre basique en Python (ex: ignore les requêtes GET simples sur la racine) et n'envoie que les requêtes comportant des caractères suspects (%, script, exec, union, etc.) à l'IA pour validation finale.
- Prompt IA : Rédige un prompt strict pour l'API locale d'Ollama afin qu'elle réponde uniquement par "MENACE" ou "SAFE".
- Sécurité : Le code Python doit être orienté objet (POO), propre et documenté en français.
- Bannissement : Pour la simulation, crée une fonction `ban_ip(ip)` qui écrit l'IP bannie dans un fichier `banned_ips.txt` avec un timestamp.

# 5. PLAN D'ACTION (Étape par étape)

Ne génère pas tout d'un coup. Procédons étape par étape.
Étape 1 : Rédige le fichier `docker-compose.yml` et le `Dockerfile` pour le service Sentinel. Attends ma validation.
Étape 2 : Une fois validé, rédige le fichier `requirements.txt` et la structure de base (les classes) de `sentinel.py`. Attends ma validation.
Étape 3 : Complète la logique interne de `sentinel.py` (lecture des logs en streaming, appel API Ollama, fonction de bannissement).

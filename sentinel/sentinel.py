"""
==========================================================
  SENTINEL RÉSEAU — Système de Détection d'Intrusions (IDS)
  Point d'entrée principal (Main)
==========================================================
"""

import os
import sys
import time
import logging

from analyzer import AnalyseurLigne
from ollama_client import ClientOllama
from ban_manager import GestionnaireBannissement

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("Sentinel")

class Sentinel:
    def __init__(self):
        self._analyseur = AnalyseurLigne()
        self._client_ia = ClientOllama()
        self._bannissement = GestionnaireBannissement()
        self._fichier_log = os.getenv("LOG_FILE", "/logs/access.log")
        self._total_lignes = 0
        self._total_suspectes = 0
        self._total_menaces = 0

        logger.info("=" * 60)
        logger.info("  SENTINEL RESEAU -- Demarrage du systeme IDS")
        logger.info("=" * 60)

    def _traiter_ligne(self, ligne: str):
        ligne = ligne.strip()
        if not ligne: return
        self._total_lignes += 1

        if not self._analyseur.est_suspecte(ligne): return
        self._total_suspectes += 1
        
        infos = self._analyseur.parser_ligne(ligne)
        if not infos: return
        ip = infos["ip"]

        if self._bannissement.est_bannie(ip): return

        logger.info(f"[IA] Analyse IP {ip} : {infos['uri']}")
        verdict = self._client_ia.analyser(ligne)

        if verdict == "MENACE":
            self._total_menaces += 1
            self._bannissement.ban_ip(ip, f"Attaque confirmée: {infos['uri']}")
        elif verdict == "SAFE":
            logger.info(f"[SAFE] Faux positif pour {ip}")

    def lancer(self):
        while not os.path.exists(self._fichier_log):
            logger.info(f"En attente de {self._fichier_log}...")
            time.sleep(2)

        logger.info("[DEMARRAGE] Surveillance activee...")
        compteur = 0
        with open(self._fichier_log, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            while True:
                ligne = f.readline()
                if ligne:
                    self._traiter_ligne(ligne)
                    compteur += 1
                    if compteur % 10 == 0:
                        logger.info(f"[STATS] Total: {self._total_lignes} | Menaces: {self._total_menaces}")
                else:
                    time.sleep(1)

if __name__ == "__main__":
    try:
        Sentinel().lancer()
    except KeyboardInterrupt:
        logger.info("[ARRET] Fin du programme.")
    except Exception as e:
        logger.critical(f"Erreur fatale : {e}")
        sys.exit(1)

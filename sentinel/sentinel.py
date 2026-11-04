"""
==========================================================
  SENTINEL RÉSEAU — Système de Détection d'Intrusions (IDS)
  Point d'entrée principal (Main)
==========================================================
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

from analyzer import AnalyseurLigne
from ban_manager import GestionnaireBannissement
from ollama_client import ClientOllama

_EXTRA_FIELDS = (
    "event",
    "ip",
    "uri",
    "verdict",
    "latency_ms",
    "reason",
    "total_lines",
    "total_threats",
)


class JsonFormatter(logging.Formatter):
    """Formate les logs applicatifs en JSON structuré (une entrée par ligne)."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _EXTRA_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _configure_logging() -> None:
    handler = logging.StreamHandler()
    if os.getenv("LOG_FORMAT", "json").lower() == "text":
        handler.setFormatter(
            logging.Formatter("[%(asctime)s] %(levelname)s — %(message)s", "%Y-%m-%d %H:%M:%S")
        )
    else:
        handler.setFormatter(JsonFormatter())

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.INFO)


_configure_logging()
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

        logger.info("SENTINEL RESEAU -- Demarrage du systeme IDS", extra={"event": "startup"})

    def _traiter_ligne(self, ligne: str):
        ligne = ligne.strip()
        if not ligne:
            return
        self._total_lignes += 1

        if not self._analyseur.est_suspecte(ligne):
            return
        self._total_suspectes += 1

        infos = self._analyseur.parser_ligne(ligne)
        if not infos:
            return
        ip = infos["ip"]

        if self._bannissement.est_bannie(ip):
            return

        logger.info(
            f"[IA] Analyse IP {ip} : {infos['uri']}",
            extra={"event": "suspicious_request", "ip": ip, "uri": infos["uri"]},
        )
        verdict = self._client_ia.analyser(ligne)

        if verdict == "MENACE":
            self._total_menaces += 1
            self._bannissement.ban_ip(ip, f"Attaque confirmée: {infos['uri']}")
        elif verdict == "SAFE":
            logger.info(
                f"[SAFE] Faux positif pour {ip}",
                extra={"event": "false_positive", "ip": ip, "uri": infos["uri"], "verdict": "SAFE"},
            )

    def lancer(self):
        while not os.path.exists(self._fichier_log):
            logger.info(f"En attente de {self._fichier_log}...")
            time.sleep(2)

        logger.info("[DEMARRAGE] Surveillance activee...", extra={"event": "watching"})
        compteur = 0
        with open(self._fichier_log, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            while True:
                ligne = f.readline()
                if ligne:
                    self._traiter_ligne(ligne)
                    compteur += 1
                    if compteur % 10 == 0:
                        logger.info(
                            f"[STATS] Total: {self._total_lignes} | Menaces: {self._total_menaces}",
                            extra={
                                "event": "stats",
                                "total_lines": self._total_lignes,
                                "total_threats": self._total_menaces,
                            },
                        )
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

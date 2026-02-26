import os
import logging
from datetime import datetime

logger = logging.getLogger("Sentinel.BanManager")

class GestionnaireBannissement:
    """
    Classe responsable du bannissement simulé des adresses IP.
    """

    def __init__(self, fichier_banni: str = None):
        self._fichier = fichier_banni or os.getenv("BANNED_FILE", "/app/data/banned_ips.txt")
        self._ips_bannies = set()
        self._charger_ips_existantes()
        logger.info(f"GestionnaireBannissement initialisé sur {self._fichier}")

    def _charger_ips_existantes(self):
        if os.path.exists(self._fichier):
            try:
                with open(self._fichier, "r", encoding="utf-8") as f:
                    for ligne in f:
                        ip = ligne.split("|")[0].strip()
                        if ip: self._ips_bannies.add(ip)
            except Exception as e:
                logger.warning(f"Erreur lecture fichier banni : {e}")

    def ban_ip(self, ip: str, raison: str = "Détectée par l'IA"):
        if ip in self._ips_bannies: return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        enregistrement = f"{ip} | {timestamp} | {raison}"

        try:
            with open(self._fichier, "a", encoding="utf-8") as f:
                f.write(enregistrement + "\n")
            self._ips_bannies.add(ip)
            logger.warning(f"[BANNI] IP BANNIE : {enregistrement}")
        except Exception as e:
            logger.error(f"Erreur écriture fichier banni : {e}")

    def est_bannie(self, ip: str) -> bool:
        return ip in self._ips_bannies

    @property
    def nombre_bannies(self):
        return len(self._ips_bannies)

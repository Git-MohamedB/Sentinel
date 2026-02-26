import re
import logging
from typing import Optional
from urllib.parse import unquote

logger = logging.getLogger("Sentinel.Analyzer")

class AnalyseurLigne:
    """
    Classe responsable du pré-filtrage des lignes de log Nginx.
    """

    MOTIFS_SUSPECTS = [
        r"%[0-9a-fA-F]{2}",    # Encodage URL (ex: %27, %3C)
        r"<script",             # Tentative de XSS
        r"</script",            # Fermeture de balise XSS
        r"javascript:",         # Injection JS
        r"onerror\s*=",         # Événement JS malveillant
        r"onload\s*=",          # Événement JS malveillant
        r"alert\s*\(",          # Appel JS suspect
        r"exec\s*\(",           # Exécution de commande
        r"union\s+select",      # Injection SQL
        r"select\s+.*\s+from",  # Injection SQL
        r"insert\s+into",       # Injection SQL
        r"drop\s+table",        # Injection SQL
        r"delete\s+from",       # Injection SQL
        r"or\s+1\s*=\s*1",     # Injection SQL classique
        r"'\s*or\s+'",          # Injection SQL avec quotes
        r"--\s*$",              # Commentaire SQL en fin de ligne
        r"\.\./",               # Traversée de répertoire
        r"/etc/passwd",         # Accès fichier sensible Linux
        r"/etc/shadow",         # Accès fichier sensible Linux
        r"/proc/self",          # Accès processus Linux
        r"cmd\.exe",            # Exécution de commande Windows
        r"powershell",          # Exécution PowerShell
        r"wget\s",              # Téléchargement distant
        r"curl\s",              # Téléchargement distant
        r"base64",              # Encodage suspect
        r"eval\s*\(",           # Évaluation de code
        r"phpinfo",             # Fuite d'informations PHP
        r"\.env",               # Accès aux variables d'environnement
        r"wp-admin",            # Scan WordPress
        r"wp-login",            # Scan WordPress
        r"\.git",               # Accès au dépôt Git
        r"\.htaccess",          # Accès configuration Apache
        r"shell",               # Détection de webshell
        r"nc\s+-",              # Netcat
    ]

    REGEX_LOG_NGINX = re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+-\s+'
        r'\[(?P<date>[^\]]+)\]\s+'
        r'"(?P<methode>\w+)\s+(?P<uri>[^\s]+)\s+[^"]*"\s+'
        r'(?P<status>\d{3})\s+'
        r'(?P<taille>\d+)'
    )

    def __init__(self):
        self._motifs_compiles = [
            re.compile(motif, re.IGNORECASE) for motif in self.MOTIFS_SUSPECTS
        ]
        logger.info(f"AnalyseurLigne initialisé avec {len(self._motifs_compiles)} motifs.")

    def parser_ligne(self, ligne: str) -> Optional[dict]:
        match = self.REGEX_LOG_NGINX.search(ligne)
        if not match:
            return None
        return match.groupdict()

    def est_suspecte(self, ligne: str) -> bool:
        # Décoder l'URL avant analyse
        ligne_decodee = unquote(ligne.replace("+", " "))

        infos = self.parser_ligne(ligne)
        if infos and infos["methode"] == "GET" and infos["uri"] in ("/", "/index.html"):
            return False

        for motif in self._motifs_compiles:
            if motif.search(ligne_decodee):
                return True

        return False

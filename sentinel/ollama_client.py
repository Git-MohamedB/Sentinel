import logging
import os
import time

import requests

logger = logging.getLogger("Sentinel.Ollama")


class ClientOllama:
    """
    Classe encapsulant la communication avec l'API locale d'Ollama.
    """

    PROMPT_SYSTEME = (
        "Tu es un expert en cybersécurité spécialisé dans l'analyse de logs de serveurs web. "
        "On te fournit une ligne de log d'un serveur Nginx. "
        "Tu dois déterminer si cette requête constitue une tentative d'attaque ou d'intrusion. "
        "Réponds UNIQUEMENT par le mot 'MENACE' si c'est une attaque, "
        "ou par le mot 'SAFE' si c'est une requête légitime. "
        "Ne donne aucune explication, aucun commentaire. Juste un seul mot : MENACE ou SAFE."
    )

    def __init__(self, hote: str = None, modele: str = "llama3:8b", timeout: int = 30):
        self._hote = hote or os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self._modele = modele
        self._timeout = timeout
        self._url_api = f"{self._hote}/api/generate"
        logger.info(f"ClientOllama initialisé sur {self._url_api}")

    def analyser(self, ligne_log: str) -> str:
        payload = {
            "model": self._modele,
            "prompt": f"Analyse cette ligne de log Nginx :\n{ligne_log}",
            "system": self.PROMPT_SYSTEME,
            "stream": False,
            "options": {"temperature": 0.0, "num_predict": 10},
        }

        start = time.perf_counter()
        try:
            reponse = requests.post(self._url_api, json=payload, timeout=self._timeout)
            reponse.raise_for_status()
            verdict = reponse.json().get("response", "").strip().upper()
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)

            if "MENACE" in verdict:
                resultat = "MENACE"
            elif "SAFE" in verdict:
                resultat = "SAFE"
            else:
                resultat = "MENACE"

            logger.info(
                f"Analyse Ollama terminée ({resultat})",
                extra={
                    "event": "ollama_inference",
                    "latency_ms": elapsed_ms,
                    "verdict": resultat,
                },
            )
            return resultat

        except Exception as e:
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            logger.error(
                f"Erreur API Ollama : {e}",
                extra={
                    "event": "ollama_error",
                    "latency_ms": elapsed_ms,
                    "verdict": "ERREUR",
                },
            )
            return "ERREUR"

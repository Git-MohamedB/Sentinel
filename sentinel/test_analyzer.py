import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ajouter le dossier actuel au path pour l'import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer import AnalyseurLigne
from ban_manager import GestionnaireBannissement
from ollama_client import ClientOllama


class TestAnalyseurLigne(unittest.TestCase):
    def setUp(self):
        self.analyseur = AnalyseurLigne()

    def test_requete_saine(self):
        """Vérifie que les requêtes normales sont acceptées."""
        lignes_saines = [
            '127.0.0.1 - - [17/Feb/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 612',
            '127.0.0.1 - - [17/Feb/2026:10:00:01 +0000] "GET /contact.html HTTP/1.1" 200 1234',
            '127.0.0.1 - - [17/Feb/2026:10:00:02 +0000] "POST /login HTTP/1.1" 401 50',
        ]
        for ligne in lignes_saines:
            self.assertFalse(self.analyseur.est_suspecte(ligne), f"Ligne saine détectée comme suspecte : {ligne}")

    def test_detection_xss(self):
        """Vérifie la détection des attaques XSS."""
        lignes_xss = [
            '127.0.0.1 - - [17/Feb/2026:10:10:00 +0000] "GET /?q=<script>alert(1)</script> HTTP/1.1" 200 612',
            '127.0.0.1 - - [17/Feb/2026:10:10:01 +0000] "GET /?name=<img src=x onerror=alert(1)> HTTP/1.1" 200 612',
        ]
        for ligne in lignes_xss:
            self.assertTrue(self.analyseur.est_suspecte(ligne), f"XSS non détecté : {ligne}")

    def test_detection_sqli(self):
        """Vérifie la détection des injections SQL."""
        lignes_sql = [
            '127.0.0.1 - - [17/Feb/2026:10:20:00 +0000] "GET /?id=1 UNION SELECT name,pass FROM users HTTP/1.1" 200 612',
            '127.0.0.1 - - [17/Feb/2026:10:20:01 +0000] "GET /?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 612',
        ]
        for ligne in lignes_sql:
            self.assertTrue(self.analyseur.est_suspecte(ligne), f"SQLi non détecté : {ligne}")

    def test_detection_traversal(self):
        """Vérifie la détection des traversées de répertoires."""
        lignes_traversal = [
            '127.0.0.1 - - [17/Feb/2026:10:30:00 +0000] "GET /../../etc/passwd HTTP/1.1" 200 612',
            '127.0.0.1 - - [17/Feb/2026:10:30:01 +0000] "GET /static/%2e%2e/%2e%2e/etc/passwd HTTP/1.1" 200 612',
        ]
        for ligne in lignes_traversal:
            self.assertTrue(self.analyseur.est_suspecte(ligne), f"Traversal non détecté : {ligne}")

    def test_encodage_url(self):
        """Vérifie que les attaques encodées sont détectées grâce au décodage URL."""
        # %3Cscript%3E est <script>
        ligne = '127.0.0.1 - - [17/Feb/2026:10:40:00 +0000] "GET /?q=%3Cscript%3E HTTP/1.1" 200 612'
        self.assertTrue(self.analyseur.est_suspecte(ligne), "Attaque encodée URL non détectée")

    def test_parser_ligne_valide_et_invalide(self):
        """Vérifie l'extraction des champs d'un log Nginx et le rejet des lignes malformées."""
        ligne = '192.168.1.42 - - [17/Feb/2026:11:00:00 +0000] "GET /admin/.env HTTP/1.1" 404 153'
        infos = self.analyseur.parser_ligne(ligne)
        self.assertIsNotNone(infos)
        self.assertEqual(infos["ip"], "192.168.1.42")
        self.assertEqual(infos["methode"], "GET")
        self.assertEqual(infos["uri"], "/admin/.env")
        self.assertEqual(infos["status"], "404")
        self.assertEqual(infos["taille"], "153")

        self.assertIsNone(self.analyseur.parser_ligne("ligne de log invalide"))


class TestGestionnaireBannissement(unittest.TestCase):
    def test_ban_deduplication_et_rechargement(self):
        """Vérifie l'ajout d'une IP, l'absence de doublon et la persistance sur disque."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fichier_banni = os.path.join(tmpdir, "banned_ips.txt")
            gestionnaire = GestionnaireBannissement(fichier_banni=fichier_banni)
            self.assertFalse(gestionnaire.est_bannie("203.0.113.10"))

            gestionnaire.ban_ip("203.0.113.10", "SQLi")
            gestionnaire.ban_ip("203.0.113.10", "SQLi répétée")
            self.assertTrue(gestionnaire.est_bannie("203.0.113.10"))
            self.assertEqual(gestionnaire.nombre_bannies, 1)

            recharge = GestionnaireBannissement(fichier_banni=fichier_banni)
            self.assertTrue(recharge.est_bannie("203.0.113.10"))
            self.assertEqual(recharge.nombre_bannies, 1)


class TestClientOllama(unittest.TestCase):
    @patch("ollama_client.requests.post")
    def test_verdict_menace(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "MENACE"}
        mock_post.return_value = mock_resp

        client = ClientOllama(hote="http://localhost:11434")
        self.assertEqual(client.analyser('GET /?q=<script>'), "MENACE")

    @patch("ollama_client.requests.post")
    def test_verdict_safe(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"response": "SAFE"}
        mock_post.return_value = mock_resp

        client = ClientOllama(hote="http://localhost:11434")
        self.assertEqual(client.analyser('GET /contact.html'), "SAFE")

    @patch("ollama_client.requests.post", side_effect=RuntimeError("timeout"))
    def test_erreur_reseau_ollama(self, _mock_post):
        client = ClientOllama(hote="http://localhost:11434")
        self.assertEqual(client.analyser('GET /'), "ERREUR")


if __name__ == '__main__':
    unittest.main()

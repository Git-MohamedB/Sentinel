import unittest
import sys
import os

# Ajouter le dossier actuel au path pour l'import
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer import AnalyseurLigne

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

if __name__ == '__main__':
    unittest.main()

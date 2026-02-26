import os
import sys
from collections import Counter
from datetime import datetime

class ReportGenerator:
    """
    Génère un rapport textuel des activités du Sentinel.
    """

    def __init__(self, fichier_banni: str = "sentinel/banned_ips.txt"):
        self._fichier = fichier_banni

    def generer(self):
        if not os.path.exists(self._fichier):
            print(f"Erreur : Le fichier {self._fichier} est introuvable.")
            return

        with open(self._fichier, "r", encoding="utf-8") as f:
            lignes = [l.strip() for l in f if l.strip()]

        if not lignes:
            print("Aucune menace détectée jusqu'à présent.")
            return

        total_bans = len(lignes)
        ips = []
        raisons = []

        for l in lignes:
            parts = l.split("|")
            if len(parts) >= 3:
                ips.append(parts[0].strip())
                raisons.append(parts[2].strip())

        top_ips = Counter(ips).most_common(5)
        top_raisons = Counter(raisons).most_common(5)

        print("=" * 60)
        print(f"🛡️ RAPPORT DE SÉCURITÉ SENTINEL — {datetime.now().strftime('%d/%m/%Y %H:%M')}")
        print("=" * 60)
        print(f"• Total des IP bannies : {total_bans}")
        
        print("\n📊 TOP DES MENACES PAR IP :")
        for ip, count in top_ips:
            print(f"  - {ip:15} : {count} incident(s)")

        print("\n🔍 TYPES DE MENACES DÉTECTÉES :")
        for raison, count in top_raisons:
            print(f"  - {raison:40} : {count} fois")
        print("=" * 60)

if __name__ == "__main__":
    # Permet de passer le fichier en argument
    path = sys.argv[1] if len(sys.argv) > 1 else "sentinel/banned_ips.txt"
    ReportGenerator(path).generer()

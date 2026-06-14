"""
extraction.py — Étapes 1 & 2
Lit les bulletins ANSSI depuis les fichiers locaux (data/)
et extrait tous les identifiants CVE présents dans chaque bulletin.
"""

import os
import json
import re
import sys

# Force l'encodage UTF-8 dans le terminal Windows
# Sans ça, les caractères spéciaux (→, ✅, accents) plantent sur Windows
sys.stdout.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

# Chemins vers les données locales fournies par le prof
DOSSIER_ALERTES = os.path.join("data", "data", "alertes")
DOSSIER_AVIS    = os.path.join("data", "data", "Avis")

# Expression régulière pour repérer les CVE dans un texte
# Format CVE : CVE-ANNÉE-NUMÉRO (ex: CVE-2024-21887)
# \d{4}   = exactement 4 chiffres (l'année)
# \d{4,7} = entre 4 et 7 chiffres (le numéro de la CVE)
CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


# ─────────────────────────────────────────────
# ÉTAPE 1 : LIRE LES BULLETINS LOCAUX
# ─────────────────────────────────────────────

def lire_bulletins(dossier, type_bulletin):
    """
    Lit tous les fichiers JSON d'un dossier (alertes ou avis)
    et retourne une liste de dictionnaires, un par bulletin.

    Paramètres :
        dossier       : chemin vers le dossier (str)
        type_bulletin : "Alerte" ou "Avis" (str)

    Retourne :
        liste de dicts avec les infos de base de chaque bulletin
    """
    bulletins = []

    # os.listdir() retourne la liste des noms de fichiers dans un dossier
    for nom_fichier in os.listdir(dossier):
        chemin = os.path.join(dossier, nom_fichier)

        # Ouverture et lecture du fichier JSON
        # encoding="utf-8" : nécessaire car les textes contiennent des accents
        try:
            with open(chemin, "r", encoding="utf-8") as f:
                data = json.load(f)   # json.load() convertit le JSON en dict Python
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"  ⚠️  Impossible de lire {nom_fichier} : {e}")
            continue   # on passe au fichier suivant sans planter

        # On construit un dictionnaire avec les infos qui nous intéressent
        # data.get("clé", valeur_par_défaut) : évite une erreur si la clé est absente
        bulletins.append({
            "id_anssi"  : data.get("reference", nom_fichier),
            "titre"     : data.get("title", "Sans titre"),
            "type"      : type_bulletin,
            "lien"      : f"https://www.cert.ssi.gouv.fr/{'alerte' if type_bulletin == 'Alerte' else 'avis'}/{data.get('reference', '')}/",
            "date"      : data.get("revisions", [{}])[0].get("revision_date", ""),
            "risques"   : [r.get("description", "") for r in data.get("risks", [])],
            "_data_brute": data,   # on garde tout le JSON pour l'étape 2
        })

    return bulletins


# ─────────────────────────────────────────────
# ÉTAPE 2 : EXTRAIRE LES CVE DE CHAQUE BULLETIN
# ─────────────────────────────────────────────

def extraire_cves(data_brute):
    """
    Extrait les identifiants CVE depuis le JSON d'un bulletin.
    Utilise deux méthodes combinées pour ne rien rater.

    Méthode 1 : la clé "cves" du JSON (liste officielle)
    Méthode 2 : regex sur tout le texte (filet de sécurité)

    Retourne une liste triée sans doublons.
    """
    # Méthode 1 — clé officielle "cves" : liste de dicts {"name": "CVE-...", "url": "..."}
    cves_officielles = {
        cve["name"]
        for cve in data_brute.get("cves", [])
        if "name" in cve
    }

    # Méthode 2 — regex sur la représentation textuelle complète du JSON
    # str(data_brute) convertit tout le dict en chaîne de caractères
    # re.findall() retourne toutes les occurrences trouvées
    cves_regex = set(re.findall(CVE_PATTERN, str(data_brute)))

    # Union des deux ensembles (|) → pas de doublons, rien de manqué
    return sorted(cves_officielles | cves_regex)


# ─────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  EXTRACTION DES BULLETINS ANSSI")
    print("=" * 55)

    # ── Étape 1 : lecture des fichiers locaux ──
    print("\n[1/2] Lecture des bulletins locaux...")

    alertes = lire_bulletins(DOSSIER_ALERTES, "Alerte")
    avis    = lire_bulletins(DOSSIER_AVIS,    "Avis")

    bulletins = alertes + avis   # on fusionne les deux listes
    print(f"  → {len(alertes)} alertes + {len(avis)} avis = {len(bulletins)} bulletins au total")

    # ── Étape 2 : extraction des CVE ──
    print("\n[2/2] Extraction des CVE...")

    for b in bulletins:
        b["cves"] = extraire_cves(b["_data_brute"])
        del b["_data_brute"]   # on supprime la donnée brute (plus utile, allège la mémoire)

    # Affichage d'un résumé
    total_cves = sum(len(b["cves"]) for b in bulletins)
    bulletins_avec_cves = sum(1 for b in bulletins if b["cves"])
    print(f"  → {total_cves} CVE extraites sur {bulletins_avec_cves}/{len(bulletins)} bulletins")

    # ── Sauvegarde intermédiaire ──
    sortie = "bulletins_bruts.json"
    with open(sortie, "w", encoding="utf-8") as f:
        json.dump(bulletins, f, ensure_ascii=False, indent=2)

    print(f"\n✅  Sauvegardé dans : {sortie}")
    print("    Tu peux l'ouvrir pour vérifier les données avant de continuer.")

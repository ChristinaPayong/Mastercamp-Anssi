"""
enrichissement.py — Étape 3
Pour chaque CVE unique, on interroge deux API :
  - API MITRE → score CVSS, type CWE, description, produits affectés
  - API FIRST → score EPSS (probabilité d'exploitation)

Optimisations :
  - Cache local : une CVE déjà téléchargée n'est jamais retéléchargée
  - EPSS en batch : 100 CVE par requête au lieu de 1 (gain x100)
  - Mode sélectif : on peut enrichir alertes seules ou tout le dataset
"""

import os
import json
import time
import sys
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.stdout.reconfigure(encoding="utf-8")

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────

HEADERS       = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
DELAI_MITRE   = 0.5     # secondes entre chaque requête MITRE (37K CVE × 0.5s ≈ 5h)
DELAI_EPSS    = 1.0     # secondes entre chaque batch EPSS (batch de 100)
BATCH_EPSS    = 100     # nombre de CVE par requête EPSS
DOSSIER_MITRE = "mitre"
DOSSIER_FIRST = "first"

os.makedirs(DOSSIER_MITRE, exist_ok=True)
os.makedirs(DOSSIER_FIRST, exist_ok=True)


# ─────────────────────────────────────────────
# CACHE MITRE (1 fichier par CVE)
# ─────────────────────────────────────────────

def recuperer_mitre(cve_id):
    """
    Récupère les données MITRE d'une CVE avec cache local.
    Si le fichier existe déjà, on le relit sans appel réseau.
    """
    chemin = os.path.join(DOSSIER_MITRE, cve_id + ".json")

    if os.path.exists(chemin):
        with open(chemin, "r", encoding="utf-8") as f:
            return json.load(f)

    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
    try:
        r = requests.get(url, headers=HEADERS, timeout=15)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            data = None   # CVE inconnue de MITRE : normal pour les vieilles CVE
        else:
            print(f"  ⚠️  MITRE {e.response.status_code} pour {cve_id}")
            return None
    except (requests.RequestException, ValueError):
        return None

    # On sauvegarde même None pour ne pas retenter les CVE introuvables
    with open(chemin, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    time.sleep(DELAI_MITRE)
    return data


# ─────────────────────────────────────────────
# BATCH EPSS (100 CVE par requête)
# ─────────────────────────────────────────────

def recuperer_epss_batch(liste_cve_ids):
    """
    Récupère les scores EPSS pour une liste de CVE en une seule requête.
    L'API FIRST accepte jusqu'à ~100 CVE séparées par des virgules.

    Retourne un dict { cve_id: score_epss }
    """
    # On filtre les CVE déjà en cache
    a_telecharger = [
        cve for cve in liste_cve_ids
        if not os.path.exists(os.path.join(DOSSIER_FIRST, cve + ".json"))
    ]

    # Résultats : on commence par lire ce qui est en cache
    resultats = {}
    for cve in liste_cve_ids:
        chemin = os.path.join(DOSSIER_FIRST, cve + ".json")
        if os.path.exists(chemin):
            with open(chemin, "r", encoding="utf-8") as f:
                data = json.load(f)
            resultats[cve] = _extraire_score_epss(data)

    if not a_telecharger:
        return resultats   # tout était en cache

    # Requête batch : CVE séparées par des virgules dans l'URL
    cves_param = ",".join(a_telecharger)
    url = f"https://api.first.org/data/v1/epss?cve={cves_param}"

    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
        data = r.json()
    except (requests.RequestException, ValueError):
        return resultats   # on retourne ce qu'on a en cache

    # L'API retourne une liste data[] avec un élément par CVE trouvée
    scores_recus = {item["cve"]: float(item.get("epss", 0)) for item in data.get("data", [])}

    # On sauvegarde chaque CVE dans son propre fichier cache
    for cve in a_telecharger:
        score = scores_recus.get(cve)   # None si l'API ne connaît pas cette CVE
        chemin = os.path.join(DOSSIER_FIRST, cve + ".json")
        with open(chemin, "w", encoding="utf-8") as f:
            json.dump({"epss": score}, f)
        resultats[cve] = score

    time.sleep(DELAI_EPSS)
    return resultats


def _extraire_score_epss(data):
    """Extrait le score d'un fichier cache EPSS."""
    if data is None:
        return None
    if "epss" in data:
        val = data["epss"]
        return float(val) if val is not None else None
    epss_data = data.get("data", [])
    if epss_data:
        return float(epss_data[0].get("epss", 0))
    return None


# ─────────────────────────────────────────────
# PARSING MITRE
# ─────────────────────────────────────────────

def parser_mitre(data):
    """Extrait les infos utiles du JSON MITRE. Gère tous les champs manquants."""
    infos = {
        "description"   : "Non disponible",
        "cvss_score"    : None,
        "base_severity" : "Non disponible",
        "cwe"           : "Non disponible",
        "cwe_desc"      : "Non disponible",
        "produits"      : [],
    }
    if not data:
        return infos

    cna = data.get("containers", {}).get("cna", {})

    # Description
    descs = cna.get("descriptions", [])
    if descs:
        infos["description"] = descs[0].get("value", "Non disponible")

    # Score CVSS (on essaie du plus récent au plus ancien)
    for metric in cna.get("metrics", []):
        for version in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if version in metric:
                infos["cvss_score"]    = metric[version].get("baseScore")
                infos["base_severity"] = metric[version].get("baseSeverity", "Non disponible")
                break
        if infos["cvss_score"] is not None:
            break

    # CWE
    pt = cna.get("problemTypes", [])
    if pt:
        d = pt[0].get("descriptions", [])
        if d:
            infos["cwe"]      = d[0].get("cweId", "Non disponible")
            infos["cwe_desc"] = d[0].get("description", "Non disponible")

    # Produits affectés
    for p in cna.get("affected", []):
        versions = [
            v.get("version", "?")
            for v in p.get("versions", [])
            if v.get("status") == "affected"
        ]
        infos["produits"].append({
            "vendor"   : p.get("vendor", "Non disponible"),
            "produit"  : p.get("product", "Non disponible"),
            "versions" : versions,
        })

    return infos


# ─────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    # argparse permet de passer des options en ligne de commande
    # Exemple : python enrichissement.py --mode alertes
    parser = argparse.ArgumentParser(description="Enrichissement des CVE ANSSI")
    parser.add_argument(
        "--mode",
        choices=["alertes", "tout"],
        default="alertes",
        help="'alertes' = enrichit seulement les CVE des alertes (rapide). "
             "'tout' = enrichit toutes les CVE (long)."
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Nombre de threads parallèles pour MITRE (défaut: 1, recommandé: 5)"
    )
    args = parser.parse_args()

    print("=" * 55)
    print("  ENRICHISSEMENT DES CVE")
    print(f"  Mode    : {args.mode.upper()}")
    print(f"  Workers : {args.workers}")
    print("=" * 55)

    # Chargement des bulletins
    with open("bulletins_bruts.json", "r", encoding="utf-8") as f:
        bulletins = json.load(f)

    # Sélection des CVE selon le mode
    if args.mode == "alertes":
        cves_uniques = sorted({
            cve
            for b in bulletins
            if b["type"] == "Alerte"
            for cve in b.get("cves", [])
        })
    else:
        cves_uniques = sorted({
            cve
            for b in bulletins
            for cve in b.get("cves", [])
        })

    print(f"\n  {len(cves_uniques)} CVE uniques à enrichir")

    # ── EPSS en batch (100 CVE à la fois) ──
    print("\n[1/2] Récupération des scores EPSS (mode batch)...")
    scores_epss = {}
    total_batches = (len(cves_uniques) + BATCH_EPSS - 1) // BATCH_EPSS

    for i in range(0, len(cves_uniques), BATCH_EPSS):
        batch = cves_uniques[i : i + BATCH_EPSS]
        scores_epss.update(recuperer_epss_batch(batch))
        num_batch = i // BATCH_EPSS + 1
        if num_batch % 10 == 0 or num_batch == total_batches:
            print(f"  Batch {num_batch}/{total_batches} traité...")

    print(f"  → {len(scores_epss)} scores EPSS récupérés")

    # ── MITRE — mode parallèle ou séquentiel ──
    enrichissement = {}
    total = len(cves_uniques)

    if args.workers > 1:
        print(f"\n[2/2] MITRE en parallèle ({args.workers} workers)...")
        verrou = threading.Lock()
        compteur = [0]

        def traiter_cve(cve_id):
            data_mitre = recuperer_mitre(cve_id)
            infos = parser_mitre(data_mitre)
            infos["epss"] = scores_epss.get(cve_id)
            with verrou:
                enrichissement[cve_id] = infos
                compteur[0] += 1
                n = compteur[0]
                if n % 500 == 0 or n == total:
                    print(f"  {n}/{total} CVE traitées...", flush=True)

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            list(executor.map(traiter_cve, cves_uniques))

    else:
        print(f"\n[2/2] Récupération des données MITRE ({DELAI_MITRE}s/CVE)...")
        for i, cve_id in enumerate(cves_uniques, start=1):
            data_mitre = recuperer_mitre(cve_id)
            infos = parser_mitre(data_mitre)
            infos["epss"] = scores_epss.get(cve_id)
            enrichissement[cve_id] = infos

            if i % 25 == 0 or i == total:
                en_cache = sum(
                    1 for c in cves_uniques[:i]
                    if os.path.exists(os.path.join(DOSSIER_MITRE, c + ".json"))
                )
                print(f"  {i}/{total} — {en_cache} depuis cache...")

    # ── Sauvegarde ──
    sortie = "cves_enrichies.json"
    with open(sortie, "w", encoding="utf-8") as f:
        json.dump(enrichissement, f, ensure_ascii=False, indent=2)

    print(f"\n✅  Sauvegardé dans : {sortie}")
    print(f"    {len(enrichissement)} CVE enrichies.")

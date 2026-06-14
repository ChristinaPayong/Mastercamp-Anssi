"""
consolidation.py — Étape 4
Assemble les bulletins ANSSI et les CVE enrichies dans un DataFrame pandas.
Règle : 1 ligne = 1 CVE dans 1 bulletin (un bulletin avec 5 CVE → 5 lignes).
Exporte le résultat en CSV pour l'analyse et la visualisation.
"""

import json
import sys
import pandas as pd   # pd est la convention universelle pour l'alias pandas

sys.stdout.reconfigure(encoding="utf-8")


# ─────────────────────────────────────────────
# CHARGEMENT DES DONNÉES
# ─────────────────────────────────────────────

def charger_donnees():
    """Charge les deux fichiers JSON produits par les étapes précédentes."""

    print("  Chargement de bulletins_bruts.json...")
    with open("bulletins_bruts.json", "r", encoding="utf-8") as f:
        bulletins = json.load(f)

    print("  Chargement de cves_enrichies.json...")
    with open("cves_enrichies.json", "r", encoding="utf-8") as f:
        cves_enrichies = json.load(f)

    return bulletins, cves_enrichies


# ─────────────────────────────────────────────
# CONSTRUCTION DU DATAFRAME
# ─────────────────────────────────────────────

def construire_dataframe(bulletins, cves_enrichies):
    """
    Construit le DataFrame ligne par ligne.
    Pour chaque bulletin, on crée UNE ligne par CVE mentionnée.
    Si un bulletin n'a pas de CVE, on garde quand même une ligne (avec CVE = None).
    """
    lignes = []

    for bulletin in bulletins:
        cves = bulletin.get("cves", [])

        # Si le bulletin n'a aucune CVE, on crée quand même une ligne
        # avec les infos du bulletin mais sans données CVE
        if not cves:
            lignes.append(_creer_ligne(bulletin, cve_id=None, infos_cve={}))
            continue

        # Pour chaque CVE du bulletin → une nouvelle ligne
        for cve_id in cves:
            # On récupère les infos enrichies de cette CVE (ou dict vide si inconnue)
            infos_cve = cves_enrichies.get(cve_id, {})
            lignes.append(_creer_ligne(bulletin, cve_id, infos_cve))

    # pd.DataFrame() construit le tableau à partir d'une liste de dicts
    # Chaque dict = une ligne, les clés = les noms de colonnes
    df = pd.DataFrame(lignes)
    return df


def _creer_ligne(bulletin, cve_id, infos_cve):
    """
    Construit un dictionnaire représentant une ligne du DataFrame.
    C'est ce dict qui deviendra une ligne dans le tableau final.
    """
    # ── Infos produits ──
    # Un CVE peut affecter plusieurs produits
    # On stocke les noms séparés par " | " pour garder tout dans une cellule
    produits = infos_cve.get("produits", [])

    vendors   = " | ".join(p.get("vendor",  "")  for p in produits) or "Non disponible"
    noms      = " | ".join(p.get("produit", "")  for p in produits) or "Non disponible"
    versions  = " | ".join(
        ", ".join(p.get("versions", []))
        for p in produits
        if p.get("versions")
    ) or "Non disponible"

    return {
        # ── Infos bulletin ANSSI ──
        "id_anssi"    : bulletin.get("id_anssi", ""),
        "titre"       : bulletin.get("titre", ""),
        "type"        : bulletin.get("type", ""),
        "date"        : bulletin.get("date", ""),
        "lien"        : bulletin.get("lien", ""),
        "risques"     : " | ".join(bulletin.get("risques", [])),

        # ── Identifiant CVE ──
        "cve_id"      : cve_id,

        # ── Données MITRE ──
        "description"   : infos_cve.get("description",   "Non disponible"),
        "cvss_score"    : infos_cve.get("cvss_score",    None),
        "base_severity" : infos_cve.get("base_severity", "Non disponible"),
        "cwe"           : infos_cve.get("cwe",           "Non disponible"),
        "cwe_desc"      : infos_cve.get("cwe_desc",      "Non disponible"),

        # ── Score EPSS ──
        "epss"          : infos_cve.get("epss", None),

        # ── Produits affectés ──
        "vendor"    : vendors,
        "produit"   : noms,
        "versions"  : versions,
    }


# ─────────────────────────────────────────────
# NETTOYAGE DES DONNÉES
# ─────────────────────────────────────────────

def nettoyer_dataframe(df):
    """
    Nettoie et convertit les colonnes pour faciliter l'analyse.
    C'est une étape cruciale : des données mal typées donnent des graphiques faux.
    """
    # ── Conversion de la date ──
    # pd.to_datetime() convertit une chaîne "2024-01-11T00:00:00" en objet datetime
    # errors="coerce" : les dates mal formatées deviennent NaT (Not a Time) au lieu de planter
    df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True)

    # On extrait des colonnes utiles pour l'analyse temporelle
    df["annee"] = df["date"].dt.year
    df["mois"]  = df["date"].dt.month

    # ── Conversion numérique ──
    # pd.to_numeric() : transforme les chaînes "8.3" en float 8.3
    # errors="coerce" : les valeurs non-numériques deviennent NaN
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["epss"]       = pd.to_numeric(df["epss"],       errors="coerce")

    # Remplacer les "Non disponible" par NaN (Not a Number = valeur manquante en pandas)
    # Cela permet aux fonctions statistiques (.mean(), .describe()) de les ignorer proprement
    # IMPORTANT : faire ce replace AVANT l'uppercase, sinon "Non disponible" devient
    # "NON DISPONIBLE" et le replace ne le trouve plus
    df.replace("Non disponible", pd.NA, inplace=True)

    # ── Normalisation de base_severity ──
    # On met tout en majuscules pour éviter les doublons "High" / "HIGH" / "high"
    df["base_severity"] = df["base_severity"].str.upper().str.strip()

    return df


# ─────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 55)
    print("  CONSOLIDATION DES DONNÉES")
    print("=" * 55)

    # ── Chargement ──
    print("\n[1/3] Chargement des fichiers...")
    bulletins, cves_enrichies = charger_donnees()
    print(f"  → {len(bulletins)} bulletins, {len(cves_enrichies)} CVE enrichies")

    # ── Construction ──
    print("\n[2/3] Construction du DataFrame...")
    df = construire_dataframe(bulletins, cves_enrichies)
    print(f"  → {len(df)} lignes × {len(df.columns)} colonnes")

    # ── Nettoyage ──
    print("\n[3/3] Nettoyage et typage des colonnes...")
    df = nettoyer_dataframe(df)

    # ── Aperçu des données ──
    print("\n── Aperçu (5 premières lignes) ──")
    # .to_string() pour afficher sans troncature
    print(df[["id_anssi", "type", "cve_id", "cvss_score", "base_severity", "epss"]].head().to_string())

    print("\n── Statistiques des colonnes numériques ──")
    print(df[["cvss_score", "epss"]].describe().round(3).to_string())

    print("\n── Répartition par type de bulletin ──")
    print(df.groupby("type")["cve_id"].count().to_string())

    print("\n── Répartition par sévérité CVSS ──")
    print(df["base_severity"].value_counts().to_string())

    # ── Export CSV ──
    sortie = "bulletins.csv"
    # index=False : on n'exporte pas la colonne d'index (0, 1, 2, ...)
    df.to_csv(sortie, index=False, encoding="utf-8-sig")
    # utf-8-sig = UTF-8 avec BOM, nécessaire pour que Excel l'ouvre correctement

    print(f"\n✅  CSV exporté : {sortie}")
    print(f"    {len(df)} lignes, {len(df.columns)} colonnes")
    print(f"    Colonnes : {list(df.columns)}")

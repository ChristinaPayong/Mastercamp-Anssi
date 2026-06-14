"""
alertes.py — Étape 7
Génère des alertes personnalisées quand des CVE critiques affectent
des produits spécifiques. Crée le sujet et le corps de l'email.
L'envoi réel est optionnel (nécessite un compte Gmail configuré).
"""

import sys
import pandas as pd
from datetime import datetime, timezone

sys.stdout.reconfigure(encoding="utf-8")


# ─────────────────────────────────────────────
# CONFIGURATION — ABONNÉS ET SEUILS
# ─────────────────────────────────────────────

# Dictionnaire des abonnés : nom → liste de produits/éditeurs surveillés
# En production, ça viendrait d'une base de données ou d'un fichier de config
ABONNES = {
    "admin_systeme": {
        "email"   : "admin@exemple.fr",
        "surveille": ["Microsoft", "Apple", "Ivanti", "Cisco"],
    },
    "dev_web": {
        "email"   : "dev@exemple.fr",
        "surveille": ["Apache", "nginx", "WordPress", "Mozilla"],
    },
    "responsable_ssi": {
        "email"   : "ssi@exemple.fr",
        "surveille": [],   # liste vide = reçoit TOUTES les alertes critiques
    },
}

# Seuils d'alerte
SEUIL_CVSS = 7.0    # CVE avec CVSS >= 7.0 (HIGH, CRITICAL)
SEUIL_EPSS = 0.5    # CVE avec EPSS >= 50% de probabilité d'exploitation
# Une CVE déclenche une alerte si elle dépasse l'UN OU L'AUTRE des seuils


# ─────────────────────────────────────────────
# CHARGEMENT ET FILTRAGE
# ─────────────────────────────────────────────

def charger_cves_critiques(chemin_csv):
    """
    Charge le CSV et filtre les CVE qui dépassent les seuils d'alerte.
    Retourne un DataFrame avec uniquement les CVE à risque élevé.
    """
    df = pd.read_csv(chemin_csv, low_memory=False)

    # Conversion des colonnes numériques
    df["cvss_score"] = pd.to_numeric(df["cvss_score"], errors="coerce")
    df["epss"]       = pd.to_numeric(df["epss"],       errors="coerce")
    df["date"]       = pd.to_datetime(df["date"], errors="coerce", utc=True)

    # Filtre : CVE qui dépassent au moins un des seuils
    # | = OU logique entre deux masques pandas
    masque_cvss = df["cvss_score"] >= SEUIL_CVSS
    masque_epss = df["epss"]       >= SEUIL_EPSS

    df_critique = df[masque_cvss | masque_epss].copy()

    # On ne garde que les lignes avec un vrai identifiant CVE
    df_critique = df_critique.dropna(subset=["cve_id"])

    return df_critique


def cves_pour_abonne(df_critique, produits_surveilles):
    """
    Filtre les CVE critiques qui concernent les produits surveillés par un abonné.
    Si produits_surveilles est vide, retourne toutes les CVE critiques.

    La recherche est insensible à la casse et cherche le nom comme sous-chaîne
    (ex: "Microsoft" trouve "Microsoft Corporation" et "Microsoft Windows")
    """
    if not produits_surveilles:
        return df_critique   # abonné universel : tout reçoit

    # On crée un masque : True si le vendor OU le produit contient un des termes surveillés
    def est_concerne(row):
        vendor  = str(row.get("vendor",  "")).lower()
        produit = str(row.get("produit", "")).lower()
        return any(
            terme.lower() in vendor or terme.lower() in produit
            for terme in produits_surveilles
        )

    masque = df_critique.apply(est_concerne, axis=1)
    return df_critique[masque]


# ─────────────────────────────────────────────
# GÉNÉRATION DES EMAILS
# ─────────────────────────────────────────────

def generer_email(nom_abonne, config_abonne, df_cves):
    """
    Génère le sujet et le corps de l'email d'alerte pour un abonné.

    Retourne un tuple (sujet, corps) ou None si aucune CVE concernée.
    """
    if df_cves.empty:
        return None   # rien à signaler pour cet abonné

    date_str  = datetime.now(timezone.utc).strftime("%d/%m/%Y")
    nb_cves   = df_cves["cve_id"].nunique()
    nb_alertes = (df_cves["type"] == "Alerte").sum()

    # ── Sujet ──
    # Court, informatif, avec niveau d'urgence visible
    niveaux = df_cves["base_severity"].dropna().unique()
    if "CRITICAL" in niveaux:
        urgence = "🚨 CRITIQUE"
    elif "HIGH" in niveaux:
        urgence = "⚠️  ÉLEVÉ"
    else:
        urgence = "ℹ️  INFO"

    sujet = f"[CERT-FR] {urgence} — {nb_cves} vulnérabilité(s) détectée(s) — {date_str}"

    # ── Corps ──
    lignes = []
    lignes.append("=" * 65)
    lignes.append("ALERTE DE SÉCURITÉ — CERT-FR ANSSI")
    lignes.append("=" * 65)
    lignes.append(f"Destinataire : {nom_abonne} <{config_abonne['email']}>")
    lignes.append(f"Date         : {date_str}")
    lignes.append(f"Produits surveillés : {', '.join(config_abonne['surveille']) or 'Tous'}")
    lignes.append("")
    lignes.append(f"RÉSUMÉ : {nb_cves} CVE à risque élevé détectées "
                  f"(dont {nb_alertes} dans des bulletins d'alerte)")
    lignes.append("")
    lignes.append("-" * 65)
    lignes.append("DÉTAIL DES VULNÉRABILITÉS")
    lignes.append("-" * 65)

    # On déduplique par CVE pour éviter les répétitions
    # (une même CVE peut apparaître dans plusieurs bulletins)
    cves_vues = set()

    for _, row in df_cves.sort_values("cvss_score", ascending=False).iterrows():
        cve_id = row.get("cve_id", "N/A")
        if cve_id in cves_vues:
            continue
        cves_vues.add(cve_id)

        cvss     = row.get("cvss_score", "N/A")
        epss     = row.get("epss", "N/A")
        severity = row.get("base_severity", "N/A")
        cwe      = row.get("cwe", "N/A")
        vendor   = row.get("vendor", "N/A")
        produit  = row.get("produit", "N/A")
        desc     = str(row.get("description", "Non disponible"))
        lien     = row.get("lien", "")
        type_b   = row.get("type", "")

        # Indicateur visuel de criticité
        if str(severity) == "CRITICAL":
            icone = "🔴"
        elif str(severity) == "HIGH":
            icone = "🟠"
        else:
            icone = "🟡"

        lignes.append(f"\n{icone} {cve_id}  |  CVSS: {cvss}  |  EPSS: {epss}  |  {severity}")
        lignes.append(f"   Éditeur  : {vendor}")
        lignes.append(f"   Produit  : {produit}")
        lignes.append(f"   Type CWE : {cwe}")
        lignes.append(f"   Bulletin : [{type_b}] {lien}")

        # Description tronquée à 200 caractères pour rester lisible
        desc_courte = desc[:200] + "..." if len(desc) > 200 else desc
        lignes.append(f"   Résumé   : {desc_courte}")

    lignes.append("")
    lignes.append("-" * 65)
    lignes.append("ACTIONS RECOMMANDÉES")
    lignes.append("-" * 65)
    lignes.append("1. Consulter les bulletins CERT-FR listés ci-dessus")
    lignes.append("2. Vérifier si vos systèmes utilisent les versions vulnérables")
    lignes.append("3. Appliquer les correctifs disponibles en priorité")
    lignes.append("4. Pour les CVE CRITICAL avec EPSS > 0.9 : action immédiate")
    lignes.append("")
    lignes.append("Source : https://www.cert.ssi.gouv.fr/")
    lignes.append("=" * 65)

    corps = "\n".join(lignes)
    return sujet, corps


# ─────────────────────────────────────────────
# ENVOI EMAIL (OPTIONNEL)
# ─────────────────────────────────────────────

def envoyer_email(destinataire, sujet, corps):
    """
    Envoie l'email via Gmail SMTP.
    ATTENTION : nécessite un "mot de passe d'application" Gmail,
    pas ton mot de passe habituel (à créer dans : compte Google
    → Sécurité → Validation en 2 étapes → Mots de passe des applications)

    Cette fonction est OPTIONNELLE. La génération du contenu (sujet + corps)
    est la partie importante, l'envoi est un bonus.
    """
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart

    # ⚠️  NE JAMAIS mettre de vrais identifiants dans le code
    # En production : utiliser des variables d'environnement
    # ex : import os; EMAIL = os.environ["EMAIL_EXPEDITEUR"]
    EMAIL_EXPEDITEUR = "votre_email@gmail.com"
    MOT_DE_PASSE_APP = "xxxx xxxx xxxx xxxx"   # mot de passe d'application Gmail

    msg = MIMEMultipart("alternative")
    msg["From"]    = EMAIL_EXPEDITEUR
    msg["To"]      = destinataire
    msg["Subject"] = sujet
    msg.attach(MIMEText(corps, "plain", "utf-8"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as serveur:
            serveur.starttls()                              # chiffrement TLS
            serveur.login(EMAIL_EXPEDITEUR, MOT_DE_PASSE_APP)
            serveur.sendmail(EMAIL_EXPEDITEUR, destinataire, msg.as_string())
        return True
    except smtplib.SMTPException as e:
        print(f"  ⚠️  Échec envoi vers {destinataire} : {e}")
        return False


# ─────────────────────────────────────────────
# PROGRAMME PRINCIPAL
# ─────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Génération d'alertes CVE personnalisées")
    parser.add_argument(
        "--envoyer",
        action="store_true",   # flag booléen : présent = True, absent = False
        help="Envoie réellement les emails (nécessite config Gmail)"
    )
    args = parser.parse_args()

    print("=" * 65)
    print("  GÉNÉRATION DES ALERTES CVE")
    print("=" * 65)

    # ── Chargement ──
    print("\n[1/3] Chargement et filtrage des CVE critiques...")
    df_critique = charger_cves_critiques("bulletins.csv")
    print(f"  → {df_critique['cve_id'].nunique()} CVE critiques "
          f"(CVSS ≥ {SEUIL_CVSS} OU EPSS ≥ {SEUIL_EPSS})")

    # ── Génération ──
    print("\n[2/3] Génération des alertes par abonné...")
    alertes_generees = []

    for nom, config in ABONNES.items():
        df_abonne = cves_pour_abonne(df_critique, config["surveille"])
        resultat  = generer_email(nom, config, df_abonne)

        if resultat is None:
            print(f"  {nom:25s} → Aucune CVE concernée")
            continue

        sujet, corps = resultat
        alertes_generees.append({
            "nom"         : nom,
            "destinataire": config["email"],
            "sujet"       : sujet,
            "corps"       : corps,
            "nb_cves"     : df_abonne["cve_id"].nunique(),
        })
        print(f"  {nom:25s} → {df_abonne['cve_id'].nunique()} CVE — {sujet}")

    # ── Affichage d'un exemple ──
    print("\n[3/3] Exemple d'email généré :")
    print()
    if alertes_generees:
        exemple = alertes_generees[0]
        print(f"SUJET : {exemple['sujet']}")
        print()
        print(exemple["corps"][:1500] + "\n[... tronqué pour l'affichage ...]")

    # ── Envoi (optionnel) ──
    if args.envoyer:
        print("\n── Envoi des emails ──")
        for alerte in alertes_generees:
            succes = envoyer_email(alerte["destinataire"], alerte["sujet"], alerte["corps"])
            statut = "✅ Envoyé" if succes else "❌ Échec"
            print(f"  {statut} → {alerte['destinataire']}")
    else:
        print("\n  (Envoi désactivé — relancer avec --envoyer pour envoyer réellement)")

    print(f"\n✅  {len(alertes_generees)} alerte(s) générée(s).")

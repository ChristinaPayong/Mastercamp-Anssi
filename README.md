# Analyse des Bulletins ANSSI — Enrichissement CVE

Outil Python d'extraction, d'enrichissement et d'analyse des bulletins de sécurité
publiés par le CERT-FR (ANSSI). Génère des alertes personnalisées pour les produits affectés.

---

## Fonctionnalités

- Extraction des bulletins ANSSI (avis et alertes) depuis les fichiers locaux
- Identification des CVE mentionnées dans chaque bulletin
- Enrichissement via les API MITRE (CVSS, CWE, produits) et FIRST (EPSS)
- Consolidation dans un DataFrame pandas exporté en CSV
- Analyse et visualisation (9 graphiques : distribution CVSS/EPSS, scatter CVSS vs EPSS, top CWE, top éditeurs, évolution temporelle)
- Machine Learning : clustering KMeans + classification Random Forest
- Génération d'alertes email personnalisées par produit surveillé

---

## Structure du projet

```
.
├── extraction.py        # Étapes 1 & 2 — lecture bulletins + extraction CVE
├── enrichissement.py    # Étape 3  — enrichissement via API MITRE et FIRST
├── consolidation.py     # Étape 4  — construction DataFrame + export CSV
├── alertes.py           # Étape 7  — génération alertes et emails
├── creer_notebook.py    # Génère analyse.ipynb
├── analyse.ipynb        # Étapes 5 & 6 — visualisations + ML
├── analyse.html         # Export HTML du notebook (livrable)
├── bulletins_bruts.json # Bulletins extraits (généré par extraction.py)
└── data/
    └── data/
        ├── alertes/     # 78 bulletins d'alertes CERTFR (JSON)
        └── Avis/        # 4025 avis de sécurité CERTFR (JSON)
```

> **Note :** `bulletins.csv` (186 MB) et `cves_enrichies.json` (50 MB) sont générés
> par le pipeline et exclus du dépôt Git. Relancer les scripts pour les reproduire.

---

## Installation

```bash
pip install pandas requests feedparser matplotlib seaborn scikit-learn plotly nbformat
```

---

## Utilisation

### Ordre d'exécution recommandé

```bash
# 1. Extraire les bulletins et les CVE
python extraction.py

# 2. Enrichir les CVE (mode rapide : alertes seulement)
python enrichissement.py --mode alertes

# 2b. Enrichir toutes les CVE en parallèle (recommandé)
python enrichissement.py --mode tout --workers 5

# 3. Construire le DataFrame et exporter le CSV
python consolidation.py

# 4. Générer et exécuter le notebook d'analyse
python creer_notebook.py
python -m nbconvert --to notebook --execute analyse.ipynb --output analyse.ipynb
python -m nbconvert --to html analyse.ipynb --output analyse.html

# 5. Générer les alertes (sans envoi email)
python alertes.py

# 5b. Générer ET envoyer les emails (nécessite config Gmail)
python alertes.py --envoyer
```

---

## Données

Les bulletins ANSSI sont fournis en local dans `data/data/` :

| Dossier | Contenu | Période |
|---------|---------|---------|
| `alertes/` | 78 alertes CERTFR | 2021 – 2025 |
| `Avis/` | 4025 avis CERTFR | 2023 – 2025 |

Les données d'enrichissement (MITRE et EPSS) sont téléchargées à la demande
et mises en cache localement dans `mitre/` et `first/` (non versionnés).

---

## Pipeline de données

```
Bulletins locaux (JSON)
        ↓
  extraction.py          → bulletins_bruts.json
        ↓
 enrichissement.py       → cves_enrichies.json
        ↓
  consolidation.py       → bulletins.csv
        ↓
   analyse.ipynb         → visualisations + modèles ML
        ↓
    alertes.py           → emails personnalisés
```

---

## Sources des données

- Bulletins ANSSI : https://www.cert.ssi.gouv.fr/
- API MITRE CVE : https://cveawg.mitre.org/api/cve/
- API FIRST EPSS : https://api.first.org/data/v1/epss

---

## Remarques techniques

- Le script `enrichissement.py` supporte le mode parallèle (`--workers N`) pour
  accélérer l'enrichissement MITRE (5 workers ≈ 3h pour 37 000 CVE).
- Un délai de 0.5s entre chaque requête respecte le rate limiting de l'API MITRE.
- Le cache local (`mitre/`, `first/`) évite de retélécharger les données déjà récupérées.
- Les fichiers de cache et données générées sont exclus du dépôt Git (voir `.gitignore`).
- L'envoi d'email nécessite un mot de passe d'application Gmail
  (à ne jamais stocker dans le code — utiliser des variables d'environnement).

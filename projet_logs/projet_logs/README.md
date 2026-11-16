# Moteur d'analyse de flux de logs sécurisé

Projet final Python - ING3
Auteur : EZ-ZARBOUHI Anass

Application en ligne de commande qui lit de gros fichiers de logs système/réseau **sans les charger en mémoire**, les nettoie, les analyse et lève des alertes de sécurité (IP blacklistées, force brute, injections, connexions hors horaires...).

## Installation

```bash
python -m venv .venv
source .venv/bin/activate          # Windows : .venv\Scripts\activate
pip install -r requirements.txt
```

Avec Conda : `conda env create -f environment.yml` puis `conda activate projet-logs`.

Le cœur du projet n'utilise que la bibliothèque standard ; `matplotlib` sert uniquement aux graphiques du notebook.

## Utilisation

```bash
# 1. générer le jeu de test (déjà présent dans data/)
python scripts/generer_logs.py

# 2. lancer le pipeline complet
python main.py

# options utiles
python main.py data/serveur_01.log --seuil 8 --fenetre 30
python main.py --max-alertes 10 --memoire --verbose

# 3. tests unitaires
python -m unittest -v
```

Les résultats sont écrits dans `output/rapport.json` et `output/audit.json`.

## Arborescence

```
.
├── main.py                  point d'entrée (CLI)
├── log_engine/
│   ├── ingestion.py         module 1 : générateurs yield / yield from
│   ├── parsing.py           module 1 : ligne -> dict, tuples (IP, port, proto)
│   ├── transformations.py   module 2 : filter, map, lambda, match-case
│   ├── aggregation.py       module 3 : set, frozenset, defaultdict
│   ├── detection.py         module 3 : force brute (while/for/break/continue/else)
│   ├── regles.py            module 4 : apply_security_rules(*args, **kwargs)
│   └── audit.py             module 4 : audit globals() / locals()
├── scripts/generer_logs.py  générateur du jeu de données
├── tests/test_pipeline.py   tests unitaires
├── data/                    logs de test + blacklist
├── rapport.ipynb            rapport / démonstration graphique
├── requirements.txt
└── environment.yml
```

## Format des logs

```
2026-11-03 08:14:22 | WARNING | 45.155.205.233:22/SSH | user=root | {"event": "login", "status": "failed", "code": 401}
2026-11-03 08:14:25 | INFO | 192.168.1.20:53/UDP | user=bob | Cron job backup.sh finished
```

Horodatage, niveau, source `IP:port/protocole`, utilisateur, puis un payload JSON ou du texte brut. Les lignes qui ne respectent pas ce format sont ignorées.

## Choix techniques

- **Mémoire constante** : tout le pipeline est fait de générateurs et d'itérateurs (`map`, `filter`). Comme un générateur ne peut être parcouru qu'une fois, `main.py` relit les fichiers pour chaque analyse au lieu de tout stocker.
- **Force brute** : seuls les événements de login sont conservés (regroupés par IP), ce qui reste petit même sur de gros volumes.
- **Règles** : une règle est une fonction `regle(record, **config) -> str | None`. Le moteur n'envoie à chaque règle que les options qu'elle déclare, donc on peut en ajouter une sans toucher au reste.
- **Robustesse** : ligne invalide -> `None` filtré ensuite, fichier absent -> avertissement, règle qui plante -> erreur loggée sans arrêter l'analyse.

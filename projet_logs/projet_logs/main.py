# Point d'entrée du projet : lance toute l'analyse des logs
# exemples :
#   python main.py
#   python main.py data/serveur_01.log --seuil 8 --fenetre 30

import argparse  # pour lire les options de la ligne de commande
import json  # pour ecrire le rapport final
import logging  # pour les messages d'avertissement
import sys  # pour le code de retour
import time  # pour mesurer le temps d'execution
from datetime import timedelta  # pour la fenetre de la force brute
from pathlib import Path  # pour les chemins

from log_engine.aggregation import agreger, charger_blacklist, comparer_ips, top  # module 3
from log_engine.audit import auditer_contexte, exporter_audit  # module 4 audit
from log_engine.detection import afficher_alerte, collecter_tentatives, detecter_force_brute  # module 3 force brute
from log_engine.ingestion import lire_plusieurs_sources  # module 1
from log_engine.regles import REGLES_PAR_DEFAUT, apply_security_rules  # module 4 regles
from log_engine.transformations import construire_pipeline  # module 2

DOSSIER_DATA = Path("data")  # dossier des logs par defaut
AFFICHAGE_MAX = 15  # nombre max d'alertes de force brute affichées


def lire_arguments():  # options de la ligne de commande
    parser = argparse.ArgumentParser(description="Analyse de logs de securité")  # le parseur
    parser.add_argument("fichiers", nargs="*", type=Path, help="fichiers .log (par defaut data/*.log)")  # fichiers a lire
    parser.add_argument("--blacklist", type=Path, default=DOSSIER_DATA / "blacklist.txt")  # fichier des ip bannies
    parser.add_argument("--seuil", type=int, default=5, help="nombre d'echecs pour une alerte")  # seuil force brute
    parser.add_argument("--fenetre", type=int, default=60, help="fenetre en secondes")  # fenetre force brute
    parser.add_argument("--max-alertes", type=int, default=None)  # pour arreter la detection plus tot
    parser.add_argument("--sortie", type=Path, default=Path("output"))  # dossier des rapports
    parser.add_argument("-v", "--verbose", action="store_true")  # pour afficher plus de messages
    return parser.parse_args()  # on renvoi les options


def titre(texte: str) -> None:  # affiche un titre de section
    print()  # ligne vide avant
    print(texte.upper())  # titre en majuscule
    print("=" * 70)  # ligne de separation


def flux(fichiers: list[Path]):  # recree un pipeline tout neuf
    # un generateur se lit qu'une seule fois donc on relit les fichiers a chaque analyse
    return construire_pipeline(lire_plusieurs_sources(fichiers))  # lecture + nettoyage + parsing


def executer(args) -> dict:  # fait toute l'analyse
    fichiers = args.fichiers or sorted(DOSSIER_DATA.glob("*.log"))  # fichiers donnés ou ceux du dossier data
    if not fichiers:  # aucun fichier
        sys.exit("Aucun fichier de log trouvé, lancer d'abord scripts/generer_logs.py")  # on arrete

    blacklist = charger_blacklist(args.blacklist)  # on charge les ip bannies
    print("Fichiers analysés :", ", ".join(str(f) for f in fichiers))  # rappel des fichiers
    print("Blacklist :", len(blacklist), "IP")  # taille de la blacklist

    # ----- partie 1 : statistiques -----
    stats = agreger(flux(fichiers))  # premier passage sur les logs
    titre("1. Statistiques generales")  # titre
    print("Logs valides :", stats.total)  # nombre total
    print("IP differentes :", len(stats.ips_actives))  # nombre d'ip
    print("IP avec des erreurs :", len(stats.ips_en_erreur))  # ip qui ont fait des erreurs
    print("\nPar niveau :")  # sous titre
    for niveau, nb in sorted(stats.par_niveau.items()):  # pour chaque niveau
        print(f"  {niveau:<9} {nb:>7}  ({100 * nb / max(stats.total, 1):.1f} %)")  # nombre et pourcentage
    print("\nCategories (match-case) :")  # sous titre
    for categorie, nb in top(stats.par_categorie, 10):  # pour chaque categorie
        print(f"  {categorie:<16} {nb:>7}")  # nombre
    print("\nUtilisateurs les plus actifs :")  # sous titre
    for user, nb in top(stats.par_utilisateur):  # top 5
        print(f"  {user:<12} {nb:>6} logs dont {stats.erreurs_par_utilisateur[user]} erreurs")  # avec les erreurs

    # ----- partie 2 : blacklist -----
    ensembles = comparer_ips(stats.ips_actives, blacklist)  # operations | & - ^
    titre("2. Comparaison avec la blacklist")  # titre
    for nom, ips in ensembles.items():  # chaque operation
        print(f"  {nom:<24} {len(ips):>4} IP")  # nombre d'ip
    if ensembles["intersection"]:  # si des ip bannies ont communiqué
        print("\n  /!\\ IP bannies qui ont quand meme communiqué :")  # avertissement
        for ip in sorted(ensembles["intersection"]):  # on les liste
            print("     -", ip)  # une par ligne

    # ----- partie 3 : force brute -----
    titre("3. Detection de force brute")  # titre
    tentatives = collecter_tentatives(flux(fichiers))  # deuxieme passage, on garde que les logins
    alertes, complete = detecter_force_brute(tentatives, seuil=args.seuil,
                                             fenetre=timedelta(seconds=args.fenetre),
                                             max_alertes=args.max_alertes)  # detection
    print(f"Parametres : {args.seuil} echecs en {args.fenetre}s\n")  # rappel des parametres
    for alerte in alertes[:AFFICHAGE_MAX]:  # on affiche les premieres
        print(" ", afficher_alerte(alerte))  # une alerte par ligne
    if len(alertes) > AFFICHAGE_MAX:  # si il y en a d'autres
        print(f"  ... ({len(alertes) - AFFICHAGE_MAX} autres dans le rapport)")  # on dit ou les trouver
    print(f"\n{len(alertes)} alerte(s), analyse {'complete' if complete else 'interrompue'}")  # resumé

    # ----- partie 4 : regles -----
    titre("4. Moteur de regles")  # titre
    resultats = apply_security_rules(*REGLES_PAR_DEFAUT, records=flux(fichiers),
                                     blacklist=blacklist, heures_ouvrees=(7, 20),
                                     max_par_regle=3)  # troisieme passage avec toutes les regles
    for regle, detail in resultats.items():  # pour chaque regle declenchée
        print(f"\n  {regle} : {detail['total']} declenchement(s)")  # le total
        for message in detail["exemples"]:  # quelques exemples
            print("    -", message)  # un par ligne

    # ----- partie 5 : audit -----
    titre("5. Audit du contexte")  # titre
    rapport_audit = auditer_contexte(globals(), locals(), etape="fin d'analyse")  # photo des variables
    chemin_audit = exporter_audit(rapport_audit, args.sortie / "audit.json")  # export json
    print(rapport_audit["nb_globales"], "globales,", rapport_audit["nb_locales"], "locales ->", chemin_audit)  # resumé

    return {  # tout ce qu'on met dans le rapport final
        "fichiers": [str(f) for f in fichiers],  # fichiers analysés
        "total": stats.total,  # nombre de logs
        "par_niveau": dict(stats.par_niveau),  # repartition par niveau
        "par_categorie": dict(stats.par_categorie),  # repartition par categorie
        "par_heure": dict(sorted(stats.par_heure.items())),  # activité par heure
        "top_utilisateurs": top(stats.par_utilisateur, 10),  # top 10
        "ips_en_erreur": sorted(stats.ips_en_erreur),  # ip avec erreurs
        "ensembles": {nom: sorted(ips) for nom, ips in ensembles.items()},  # resultats des ensembles
        "force_brute": [dict(a, cibles=sorted(a["cibles"])) for a in alertes],  # toutes les alertes
        "regles": resultats,  # resultats des regles
    }


def main() -> int:  # fonction principale
    args = lire_arguments()  # on lit les options
    niveau = logging.INFO if args.verbose else logging.WARNING  # plus de messages en mode verbose
    logging.basicConfig(level=niveau, format="%(levelname)s : %(message)s")  # config des messages

    debut = time.perf_counter()  # chrono de depart
    try:  # l'utilisateur peut faire Ctrl+C
        rapport = executer(args)  # toute l'analyse
    except KeyboardInterrupt:  # Ctrl+C
        print("\nAnalyse arretée par l'utilisateur")  # message
        return 130  # code de retour classique pour Ctrl+C
    duree = time.perf_counter() - debut  # temps total
    rapport["duree_s"] = round(duree, 2)  # on l'ajoute au rapport

    args.sortie.mkdir(parents=True, exist_ok=True)  # on cree le dossier de sortie
    chemin = args.sortie / "rapport.json"  # chemin du rapport
    with open(chemin, "w", encoding="utf-8") as f:  # ouverture en ecriture
        json.dump(rapport, f, ensure_ascii=False, indent=2, default=str)  # ecriture du json

    titre("Terminé")  # fin
    print(f"Durée : {duree:.2f}s")  # temps
    print("Rapport complet :", chemin)  # ou trouver le rapport
    return 0  # tout s'est bien passé


if __name__ == "__main__":  # seulement si on lance ce fichier directement
    sys.exit(main())  # on lance le programme

# Module 3 : on compte tout avec des set, frozenset et defaultdict

from collections import defaultdict  # dict qui cree la cle tout seul si elle existe pas
from pathlib import Path  # pour les chemins
from typing import Iterable  # pour le typage

from .parsing import ip_valide  # pour verifier les ip de la blacklist
from .transformations import eclater, router  # pour le routage match-case

NIVEAUX_ERREUR = frozenset({"ERROR", "CRITICAL"})  # les niveaux qu'on considere comme erreur


def charger_blacklist(chemin: str | Path) -> frozenset[str]:  # lit le fichier des ip bannies
    ips = set()  # set vide pour stocker les ip
    try:  # le fichier existe peut etre pas
        with open(chemin, encoding="utf-8") as f:  # ouverture du fichier
            for ligne in f:  # ligne par ligne
                ip = ligne.split("#")[0].strip()  # on enleve les commentaires et les espaces
                if ip == "":  # ligne vide
                    continue  # on passe a la suivante
                if ip_valide(ip):  # si l'ip est correcte
                    ips.add(ip)  # on l'ajoute
    except FileNotFoundError:  # pas de fichier
        return frozenset()  # blacklist vide
    return frozenset(ips)  # frozenset car la blacklist doit pas changer pendant l'analyse


class Statistiques:  # regroupe tout les compteurs
    def __init__(self) -> None:  # on initialise tout a vide
        self.total = 0  # nombre de logs
        self.ips_actives = set()  # toutes les ip vues (set = pas de doublon)
        self.ips_en_erreur = set()  # ip qui ont fait des erreurs
        self.par_niveau = defaultdict(int)  # nombre de logs par niveau
        self.par_utilisateur = defaultdict(int)  # nombre de logs par utilisateur
        self.erreurs_par_utilisateur = defaultdict(int)  # nombre d'erreurs par utilisateur
        self.par_categorie = defaultdict(int)  # nombre par categorie du match-case
        self.par_heure = defaultdict(int)  # nombre de logs par heure
        self.ports_par_ip = defaultdict(set)  # les ports utilisés par chaque ip

    def ajouter(self, log: dict) -> None:  # met a jour les compteurs avec un log
        ip = log["ip"]  # l'ip du log
        self.total += 1  # un log de plus
        self.ips_actives.add(ip)  # on ajoute l'ip (si elle y est deja sa change rien)
        self.par_niveau[log["level"]] += 1  # pas de KeyError grace au defaultdict
        self.par_utilisateur[log["user"]] += 1  # pareil pour l'utilisateur
        self.par_heure[log["timestamp"].hour] += 1  # pareil pour l'heure
        self.ports_par_ip[ip].add(log["source"][1])  # on note le port utilisé

        if log["level"] in NIVEAUX_ERREUR:  # si c'est une erreur
            self.ips_en_erreur.add(ip)  # on note l'ip
            self.erreurs_par_utilisateur[log["user"]] += 1  # et une erreur de plus pour l'utilisateur

        for element in eclater(log):  # on decoupe le log en morceaux
            categorie, detail = router(element)  # on recupere la categorie
            self.par_categorie[categorie] += 1  # on compte


def agreger(logs: Iterable[dict]) -> Statistiques:  # parcour tout les logs une seule fois
    stats = Statistiques()  # on cree l'objet vide
    for log in logs:  # pour chaque log
        stats.ajouter(log)  # on met a jour
    return stats  # on renvoi les stats


def comparer_ips(actives: set[str], blacklist: frozenset[str]) -> dict[str, frozenset[str]]:  # operations d'ensembles
    return {  # dict avec les 5 operations
        "union": frozenset(actives | blacklist),  # toutes les ip actives ou bannies
        "intersection": frozenset(actives & blacklist),  # ip bannies qui ont quand meme communiqué (le plus grave)
        "actives_hors_blacklist": frozenset(actives - blacklist),  # ip actives normales
        "blacklist_inactives": frozenset(blacklist - actives),  # ip bannies qu'on a pas vu
        "difference_symetrique": frozenset(actives ^ blacklist),  # ip presentes que d'un seul coté
    }


def top(compteur: dict, n: int = 5) -> list[tuple]:  # les n plus gros du compteur
    return sorted(compteur.items(), key=lambda x: x[1], reverse=True)[:n]  # tri decroissant avec une lambda

# Module 1 : lecture des fichiers de log avec des generateurs
# le but c'est de pas charger tout le fichier dans la RAM d'un coup

import logging  # pour afficher les avertissement
from pathlib import Path  # pour gerer les chemins des fichiers
from typing import Iterable, Iterator  # pour le typage des fonctions

logger = logging.getLogger(__name__)  # on cree le logger de ce module


def lire_logs(chemin: str | Path) -> Iterator[str]:  # generateur qui lit un fichier
    chemin = Path(chemin)  # on transforme le chemin en objet Path
    try:  # on essaye d'ouvrir le fichier
        with open(chemin, "r", encoding="utf-8", errors="replace") as f:  # ouverture en lecture
            for ligne in f:  # on parcour le fichier ligne par ligne
                yield ligne.rstrip("\n")  # on renvoi la ligne sans le retour a la ligne
    except FileNotFoundError:  # si le fichier existe pas
        logger.warning("Fichier introuvable : %s", chemin)  # on previent mais on plante pas
    except PermissionError:  # si on a pas le droit de le lire
        logger.warning("Pas les droits pour lire : %s", chemin)  # pareil on previent juste


def lire_plusieurs_sources(chemins: Iterable[str | Path]) -> Iterator[str]:  # lit plusieur fichiers
    for chemin in chemins:  # pour chaque fichier de la liste
        logger.info("Lecture de %s", chemin)  # message si on est en mode verbose
        yield from lire_logs(chemin)  # on delegue au premier generateur avec yield from


def flux_simule(lignes: Iterable[str]) -> Iterator[str]:  # pour faire des test sans fichier
    yield from lignes  # on renvoi les lignes une par une

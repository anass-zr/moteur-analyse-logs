# Module 4 (suite) : audit des variables en memoire avec globals() et locals()
# une fonction peut pas lire les locals() d'une autre donc l'appelant nous les donne

import json  # pour exporter le rapport
import sys  # pour la taille des variables
import types  # pour reconnaitre les modules et les fonctions
from datetime import datetime  # pour la date du rapport
from pathlib import Path  # pour le chemin du fichier


def decrire_variable(nom: str, valeur) -> dict:  # infos sur une variable
    infos = {  # dict avec les infos de base
        "nom": nom,  # nom de la variable
        "type": type(valeur).__name__,  # son type
        "taille_octets": sys.getsizeof(valeur),  # place en memoire
    }
    try:  # tout les objets ont pas de len
        infos["longueur"] = len(valeur)  # nombre d'elements si c'est une collection
    except TypeError:  # pas de len
        pass  # on met rien
    apercu = repr(valeur)  # representation texte de la valeur
    if len(apercu) > 80:  # si c'est trop long
        apercu = apercu[:77] + "..."  # on coupe
    infos["apercu"] = apercu  # on ajoute l'apercu
    return infos  # on renvoi


def decrire_portee(portee: dict, avec_fonctions: bool = False) -> list[dict]:  # decrit toutes les variables d'une portée
    resultat = []  # liste des descriptions
    for nom in sorted(portee):  # on trie par nom
        valeur = portee[nom]  # la valeur de la variable
        if nom.startswith("__"):  # variables internes de python
            continue  # on les ignore
        if isinstance(valeur, (types.ModuleType, type)):  # modules importés et classes
            continue  # sinon le rapport est illisible
        if isinstance(valeur, (types.FunctionType, types.BuiltinFunctionType)) and not avec_fonctions:  # fonctions
            continue  # on les met que si on a demandé
        resultat.append(decrire_variable(nom, valeur))  # on ajoute la description
    return resultat  # liste finale


def auditer_contexte(portee_globale: dict, portee_locale: dict, etape: str = "") -> dict:  # construit le rapport
    globales = decrire_portee(portee_globale, avec_fonctions=True)  # variables globales
    locales = decrire_portee(portee_locale)  # variables locales
    rapport = {  # le rapport final
        "date": datetime.now().isoformat(timespec="seconds"),  # date de l'audit
        "etape": etape,  # a quel moment du programme
        "python": sys.version.split()[0],  # version de python
        "nb_globales": len(globales),  # nombre de globales
        "nb_locales": len(locales),  # nombre de locales
        "memoire_locales_octets": sum(v["taille_octets"] for v in locales),  # memoire totale des locales
        "globales": globales,  # detail des globales
        "locales": locales,  # detail des locales
    }
    rapport["portee_audit"] = sorted(locals().keys())  # les variables de cette fonction elle meme
    return rapport  # on renvoi


def exporter_audit(rapport: dict, chemin: str | Path) -> Path:  # ecrit le rapport en json
    chemin = Path(chemin)  # objet Path
    chemin.parent.mkdir(parents=True, exist_ok=True)  # on cree le dossier si il existe pas
    with open(chemin, "w", encoding="utf-8") as f:  # ouverture en ecriture
        json.dump(rapport, f, ensure_ascii=False, indent=2, default=str)  # default=str pour les dates
    return chemin  # on renvoi le chemin

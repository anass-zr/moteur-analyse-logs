# Module 4 : moteur de regles de securité
# une regle c'est juste une fonction qui prend un log et renvoi un message ou None

import logging  # pour afficher les erreurs des regles
import re  # pour chercher les motifs d'attaque
from collections import defaultdict  # pour compter sans KeyError
from typing import Callable  # pour le typage

logger = logging.getLogger(__name__)  # logger du module

# motifs d'injection qu'on cherche dans les messages (sql, xss, fichiers systeme)
MOTIFS_SUSPECTS = re.compile(r"(union\s+select|or\s+1\s*=\s*1|drop\s+table|<script|\.\./\.\./|/etc/passwd)", re.IGNORECASE)


def regle_ip_blacklistee(log: dict, **options) -> str | None:  # ip qui est dans la blacklist
    blacklist = options.get("blacklist", frozenset())  # on recupere la blacklist dans les options
    if log["ip"] in blacklist:  # si l'ip est bannie
        return f"IP blacklistée active : {log['ip']}"  # alerte
    return None  # rien a signaler


def regle_niveau_critique(log: dict, **options) -> str | None:  # evenement critique
    if log["level"] == "CRITICAL":  # niveau le plus grave
        return f"Evenement critique : {log['resume']}"  # alerte
    return None  # rien


def regle_heure_nocturne(log: dict, **options) -> str | None:  # connexion reussie la nuit
    debut, fin = options.get("heures_ouvrees", (7, 20))  # horaires de travail, 7h-20h par defaut
    heure = log["timestamp"].hour  # heure du log
    payload = log["payload"]  # le message
    if not isinstance(payload, dict):  # si c'est du texte
        return None  # c'est pas un login
    if payload.get("event") == "login" and payload.get("status") == "success":  # connexion reussie
        if heure < debut or heure >= fin:  # en dehors des horaires
            return f"Connexion hors horaires ({heure}h) de {log['user']}"  # alerte
    return None  # rien


def regle_compte_sensible(log: dict, **options) -> str | None:  # probleme sur root ou admin
    comptes = options.get("comptes_sensibles", frozenset({"root", "admin"}))  # comptes a surveiller
    if log["user"] in comptes and log["level"] != "INFO":  # compte sensible et pas un log normal
        return f"Activité anormale sur compte sensible '{log['user']}'"  # alerte
    return None  # rien


def regle_payload_suspect(log: dict, **options) -> str | None:  # tentative d'injection
    texte = str(log["payload"])  # on met le payload en texte meme si c'est un dict
    trouve = MOTIFS_SUSPECTS.search(texte)  # on cherche un motif dangereux
    if trouve:  # si on en a trouvé un
        return f"Motif d'injection '{trouve.group(0)}' depuis {log['ip']}"  # alerte avec le motif
    return None  # rien


REGLES_PAR_DEFAUT = (  # tuple des regles utilisées par defaut
    regle_ip_blacklistee,  # les fonctions sont rangées comme des objets normaux
    regle_niveau_critique,
    regle_heure_nocturne,
    regle_compte_sensible,
    regle_payload_suspect,
)


def apply_security_rules(*args: Callable, **kwargs) -> dict:  # *args = les regles, **kwargs = la config
    if "records" not in kwargs:  # les logs sont obligatoires
        raise ValueError("apply_security_rules : il manque le parametre records")  # on bloque
    logs = kwargs.pop("records")  # on recupere les logs et on les enleve des options
    max_par_regle = kwargs.pop("max_par_regle", 50)  # nombre max d'exemples gardés par regle

    regles = []  # liste des vraies regles
    for r in args:  # on verifie chaque argument
        if callable(r):  # si c'est une fonction
            regles.append(r)  # on la garde
        else:  # sinon
            logger.warning("Argument ignoré car c'est pas une fonction : %r", r)  # on previent

    exemples = defaultdict(list)  # nom de la regle -> messages
    compteurs = defaultdict(int)  # nom de la regle -> nombre de declenchements

    for log in logs:  # on parcour les logs une seule fois
        for regle in regles:  # chaque log passe dans chaque regle
            try:  # une regle buggée doit pas tout planter
                message = regle(log, **kwargs)  # on appelle la regle avec la config
            except Exception as e:  # si la regle plante
                logger.error("La regle %s a planté : %s", regle.__name__, e)  # on affiche l'erreur
                continue  # et on passe a la regle suivante
            if message is None:  # la regle a rien trouvé
                continue  # regle suivante
            compteurs[regle.__name__] += 1  # un declenchement de plus
            if len(exemples[regle.__name__]) < max_par_regle:  # si on a pas encore trop d'exemples
                exemples[regle.__name__].append(message)  # on garde le message

    resultat = {}  # dict final
    for nom in compteurs:  # pour chaque regle qui s'est declenchée
        resultat[nom] = {"total": compteurs[nom], "exemples": exemples[nom]}  # total + exemples
    return resultat  # on renvoi le tout

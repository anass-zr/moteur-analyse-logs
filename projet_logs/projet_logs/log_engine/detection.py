# Module 3 (suite) : detection des attaques par force brute
# idee : si une meme ip rate sa connexion plein de fois d'affilé en peu de temps c'est louche

from collections import defaultdict  # pour regrouper les tentatives par ip
from datetime import timedelta  # pour la fenetre de temps
from typing import Iterable  # pour le typage


def collecter_tentatives(logs: Iterable[dict]) -> defaultdict:  # garde que les logins
    tentatives = defaultdict(list)  # ip -> liste de tentatives
    for log in logs:  # on parcour les logs
        payload = log["payload"]  # le message
        if not isinstance(payload, dict):  # si c'est du texte
            continue  # c'est pas un login, on passe
        if payload.get("event") != "login":  # si c'est pas un evenement de connexion
            continue  # on passe aussi
        reussi = payload.get("status") == "success"  # True si la connexion a marché
        tentatives[log["ip"]].append((log["timestamp"], reussi, log["user"]))  # tuple (date, reussi, user)
    return tentatives  # beaucoup plus leger que de garder tout les logs


def afficher_alerte(alerte: dict) -> str:  # transforme une alerte en texte lisible
    cibles = ", ".join(sorted(alerte["cibles"]))  # les utilisateurs visés
    duree = int((alerte["fin"] - alerte["debut"]).total_seconds())  # durée de l'attaque en secondes
    return f"{alerte['ip']:>15} | {alerte['echecs']:>3} echecs en {duree:>3}s | cibles : {cibles} | {alerte['statut']}"  # ligne finale


def detecter_force_brute(tentatives_par_ip: dict, seuil: int = 5,
                         fenetre: timedelta = timedelta(seconds=60),
                         max_alertes: int | None = None) -> tuple[list[dict], bool]:  # renvoi (alertes, analyse finie ou pas)
    if seuil < 1:  # un seuil de 0 a pas de sens
        raise ValueError("Le seuil doit etre au moins 1")  # on bloque

    alertes = []  # liste des alertes trouvées
    analyse_complete = False  # devient True seulement dans le else de la boucle

    for ip, tentatives in tentatives_par_ip.items():  # on regarde chaque ip
        if len(tentatives) < seuil:  # pas assez de tentatives pour atteindre le seuil
            continue  # inutil de chercher, ip suivante

        tentatives = sorted(tentatives)  # on trie par date
        i = 0  # position dans la liste
        while i < len(tentatives):  # tant qu'on est pas a la fin
            debut, reussi, _ = tentatives[i]  # la tentative ou on commence
            if reussi:  # si elle a reussi
                i += 1  # une serie d'echecs peut pas commencer par un succes
                continue  # on avance

            echecs = 0  # compteur d'echecs de la serie
            fin = debut  # date du dernier echec
            cibles = set()  # utilisateurs visés
            for date, ok, utilisateur in tentatives[i:]:  # on avance a partir de i
                if date - debut > fenetre:  # on depasse la fenetre de temps
                    statut = "terminée"  # la serie est finie
                    break  # on arrete de compter
                if ok:  # une connexion reussie arrive
                    statut = "SUCCES juste apres (compte compromis ?)"  # le pire cas
                    break  # sa casse la serie
                echecs += 1  # un echec de plus
                fin = date  # on met a jour la fin
                cibles.add(utilisateur)  # on note l'utilisateur visé
            else:  # on arrive ici seulement si y a pas eu de break
                statut = "toujours en cours en fin de journal"  # le fichier finit pendant l'attaque

            if echecs >= seuil:  # on a atteint le seuil
                alertes.append({  # on cree l'alerte
                    "ip": ip,  # l'ip de l'attaquant
                    "echecs": echecs,  # nombre d'echecs
                    "debut": debut,  # debut de l'attaque
                    "fin": fin,  # fin de l'attaque
                    "cibles": frozenset(cibles),  # utilisateurs visés
                    "statut": statut,  # comment sa c'est fini
                })
                i += echecs  # on saute la serie qu'on vient de signaler
            else:  # pas assez d'echecs
                i += 1  # on essaye a partir de la tentative suivante

        if max_alertes is not None and len(alertes) >= max_alertes:  # si on a deja trop d'alertes
            break  # on arrete tout
    else:  # pas de break = toutes les ip ont été analysées
        analyse_complete = True  # l'analyse est complete

    return alertes, analyse_complete  # on renvoi les deux

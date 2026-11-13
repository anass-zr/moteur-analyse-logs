# Module 2 : pipeline avec filter, map, lambda et match-case
# filter et map renvoient des iterateurs donc rien est calculé tant qu'on demande pas

from typing import Any, Callable, Iterable, Iterator  # pour le typage

from .parsing import parser_ligne  # la fonction qui transforme une ligne en dict


def nettoyer_lignes(lignes: Iterable[str]) -> Iterator[str]:  # enleve les lignes vides et les commentaires
    non_vides = filter(None, map(str.strip, lignes))  # strip enleve les espaces, filter(None) vire les lignes vides
    return filter(lambda l: not l.startswith("#"), non_vides)  # lambda pour enlever les commentaires


def est_requete_valide(log: dict) -> bool:  # on enleve le bruit qui sert a rien
    payload = log["payload"]  # on recupere le message
    match payload:  # on regarde la forme du payload
        case "":  # texte vide
            return False  # invalide
        case dict() if len(payload) == 0:  # dictionaire vide (attention {} tout seul marche pas)
            return False  # invalide
        case {"event": "healthcheck"}:  # les healthcheck c'est juste le serveur qui verifie qu'il marche
            return False  # on les garde pas
        case str() if payload.lower().startswith("healthcheck"):  # pareil mais en texte
            return False  # on les garde pas
    return True  # tout le reste est valide


def filtrer(logs: Iterable[dict], *predicats: Callable[[dict], bool]) -> Iterator[dict]:  # applique plusieur filtres
    resultat = logs  # au debut on a tout les logs
    for predicat in predicats:  # pour chaque fonction de filtre
        resultat = filter(predicat, resultat)  # on rajoute un filter par dessus
    return iter(resultat)  # on renvoi un iterateur


def normaliser(log: dict) -> dict:  # met le log au propre
    payload = log["payload"]  # on recupere le message
    if isinstance(payload, dict):  # si c'est un dictionaire
        nouveau = {}  # on fait un nouveau dict
        for cle, valeur in payload.items():  # on parcour les cles
            nouveau[str(cle).strip().lower()] = valeur  # cles en minuscule sans espace
        payload = nouveau  # on remplace
    else:  # si c'est du texte
        payload = " ".join(payload.split())  # on enleve les espaces en trop

    ip, port, proto = log["source"]  # on deballe le tuple
    utilisateur = log["user"].strip().lower()  # nom en minuscule
    date = log["timestamp"].strftime("%Y-%m-%d %H:%M:%S")  # date en texte
    resume = f"[{date}] {log['level']:<8} {ip:>15}:{port:<5} {proto:<5} user={utilisateur}"  # resume aligné avec une f-string

    nouveau_log = dict(log)  # copie pour pas modifier l'original
    nouveau_log["user"] = utilisateur  # on met le nom propre
    nouveau_log["payload"] = payload  # on met le payload propre
    nouveau_log["resume"] = resume  # on rajoute le resume
    return nouveau_log  # on renvoi la copie


def construire_pipeline(lignes: Iterable[str], *filtres_supp: Callable[[dict], bool]) -> Iterator[dict]:  # toute la chaine
    lignes_propres = nettoyer_lignes(lignes)  # etape 1 : nettoyage
    logs = filter(None, map(parser_ligne, lignes_propres))  # etape 2 : parsing et on vire les None
    valides = filtrer(logs, est_requete_valide, *filtres_supp)  # etape 3 : filtrage
    return map(normaliser, valides)  # etape 4 : normalisation


def eclater(log: dict) -> Iterator[Any]:  # decoupe un log en morceaux de formes differentes
    payload = log["payload"]  # le message
    statut = {"level": log["level"]}  # morceau 1 : un dict avec le niveau
    if isinstance(payload, dict) and "code" in payload:  # si il y a un code dans le payload
        statut["code"] = payload["code"]  # on le rajoute
    yield statut  # on renvoi le dict
    yield log["source"]  # morceau 2 : le tuple de connexion
    if isinstance(payload, str):  # si le message est du texte
        yield payload  # morceau 3 : la chaine brute


def router(element: Any) -> tuple[str, str]:  # range un element dans une categorie avec match-case
    match element:  # on regarde la forme de l'element
        case {"level": "ERROR" | "CRITICAL" as niveau, "code": int(code)}:  # erreur avec un code
            return "erreur", f"{niveau} code={code}"  # categorie erreur
        case {"level": "ERROR" | "CRITICAL" as niveau}:  # erreur sans code
            return "erreur", f"{niveau} sans code"  # categorie erreur aussi
        case {"level": str(niveau), "code": int(code)}:  # pas une erreur mais avec un code
            return "statut", f"{niveau} code={code}"  # simple statut
        case {"level": str(niveau)}:  # pas une erreur sans code
            return "statut", niveau  # simple statut
        case (str(ip), int(port), "SSH" | "TELNET" as proto):  # connexion d'administration
            return "connexion_admin", f"{proto} {ip}:{port}"  # ssh ou telnet = acces admin
        case (str(ip), int(port), str(proto)):  # connexion normale
            return "connexion", f"{proto} {ip}:{port}"  # connexion classique
        case str() as texte if texte != "":  # texte brut pas vide
            return "brut", texte[:60]  # on garde que le debut du texte
        case _:  # tout le reste
            return "inconnu", str(element)[:60]  # forme qu'on reconnait pas

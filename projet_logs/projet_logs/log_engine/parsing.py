# Module 1 (suite) : on transforme une ligne de texte en dictionaire
# format d'une ligne :
# 2026-11-03 08:14:22 | ERROR | 192.168.1.20:22/SSH | user=alice | {...}

import json  # pour lire le payload quand c'est du json
from datetime import datetime  # pour convertir la date

NIVEAUX = ("INFO", "WARNING", "ERROR", "CRITICAL")  # tuple car la liste change jamais
FORMAT_DATE = "%Y-%m-%d %H:%M:%S"  # format de la date dans les logs


def ip_valide(ip: str) -> bool:  # verifie qu'une ip est correcte
    morceaux = ip.split(".")  # on coupe l'ip sur les points
    if len(morceaux) != 4:  # une ip a forcement 4 morceaux
        return False  # sinon c'est pas une ip
    for m in morceaux:  # on regarde chaque morceau
        if not m.isdigit():  # si c'est pas un nombre
            return False  # ip invalide
        if int(m) > 255:  # un octet va de 0 a 255
            return False  # sinon ip invalide
    return True  # tout est bon


def parser_source(texte: str) -> tuple[str, int, str] | None:  # "10.0.0.1:443/TCP" -> tuple
    texte = texte.strip()  # on enleve les espaces autour
    if ":" not in texte:  # il faut le : entre l'ip et le port
        return None  # sinon le format est pas bon
    ip, reste = texte.split(":", 1)  # on separe l'ip du reste
    if "/" not in reste:  # il faut le / entre le port et le protocole
        return None  # format pas bon
    port, proto = reste.split("/", 1)  # on separe le port et le protocole
    if not ip_valide(ip) or not port.isdigit() or not proto.isalpha():  # on verifie les 3 morceaux
        return None  # un des morceaux est faux
    port = int(port)  # on convertit le port en entier
    if port < 1 or port > 65535:  # un port va de 1 a 65535
        return None  # port impossible
    return (ip, port, proto.upper())  # tuple car ces infos doivent pas changer


def parser_payload(texte: str) -> dict | str:  # le payload c'est du json ou du texte
    texte = texte.strip()  # on enleve les espaces
    if texte.startswith("{"):  # si sa ressemble a du json
        try:  # on essaye de le lire
            contenu = json.loads(texte)  # conversion json -> dict
            if isinstance(contenu, dict):  # on verifie que c'est bien un dictionaire
                return contenu  # on renvoi le dict
        except json.JSONDecodeError:  # si le json est cassé
            pass  # on le garde comme du texte normal
    return texte  # sinon on renvoi le texte tel quel


def parser_ligne(ligne: str) -> dict | None:  # renvoi un dict ou None si la ligne est pourrie
    champs = ligne.split(" | ", 4)  # on coupe en 5 morceaux maximum
    if len(champs) != 5:  # si il en manque
        return None  # ligne inutilisable

    date_txt, niveau, source_txt, user_txt, payload_txt = champs  # on recupere les 5 morceaux

    try:  # la date peut etre fausse
        date = datetime.strptime(date_txt.strip(), FORMAT_DATE)  # texte -> vraie date
    except ValueError:  # date impossible genre 25h61
        return None  # on jete la ligne

    niveau = niveau.strip().upper()  # on met le niveau en majuscule
    if niveau not in NIVEAUX:  # si c'est un niveau qu'on connait pas
        return None  # on jete la ligne

    source = parser_source(source_txt)  # on decoupe ip, port, protocole
    if source is None:  # si la source est fausse
        return None  # on jete la ligne

    user_txt = user_txt.strip()  # on enleve les espaces
    if not user_txt.startswith("user="):  # le champ doit commencer par user=
        return None  # sinon on jete
    utilisateur = user_txt[5:]  # on enleve le "user=" du debut
    if utilisateur == "":  # si y a pas de nom
        utilisateur = "anonyme"  # on met anonyme par defaut

    return {  # on construit le dictionaire final
        "timestamp": date,  # la date
        "level": niveau,  # le niveau de gravité
        "source": source,  # le tuple (ip, port, protocole)
        "ip": source[0],  # l'ip a part pour aller plus vite apres
        "user": utilisateur,  # le nom d'utilisateur
        "payload": parser_payload(payload_txt),  # le message (dict ou texte)
    }

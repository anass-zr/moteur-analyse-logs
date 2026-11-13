"""Génère un jeu de données de test réaliste (avec du bruit et des attaques).

Usage :
    python scripts/generer_logs.py --lignes 15000 --fichiers 3 --sortie data
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta
from pathlib import Path

UTILISATEURS = ["alice", "bob", "karim", "sarah", "ines", "lucas", "yanis",
                "emma", "admin", "root", "svc_backup"]
IPS_INTERNES = [f"192.168.1.{i}" for i in range(10, 60)] + \
               [f"10.0.0.{i}" for i in range(2, 30)]
IPS_EXTERNES = ["185.220.101.4", "45.155.205.233", "103.75.190.12",
                "91.240.118.172", "194.26.29.113", "77.83.36.61"]
BLACKLIST = ["185.220.101.4", "45.155.205.233", "91.240.118.172",
             "5.188.206.14", "212.70.149.10"]
SERVICES = [(22, "SSH"), (443, "TCP"), (80, "HTTP"), (3306, "TCP"),
            (21, "FTP"), (53, "UDP"), (23, "TELNET")]
MESSAGES_BRUTS = [
    "Connection closed by peer",
    "Disk usage at 91% on /var",
    "Session timeout after 900s",
    "Cron job backup.sh finished",
    "Certificate will expire in 12 days",
    "Healthcheck OK",
    "   Unexpected   EOF   while reading   socket  ",
]
CHEMINS = ["/api/users", "/login", "/dashboard", "/api/export"]
INJECTIONS = ["/search?q=' OR 1=1 --", "/item?id=1 UNION SELECT password",
              "/../../etc/passwd", "<script>alert(1)</script>"]


def ligne(ts: datetime, niveau: str, ip: str, port: int, proto: str,
          user: str, payload: dict | str) -> str:
    contenu = json.dumps(payload) if isinstance(payload, dict) else payload
    return (f"{ts:%Y-%m-%d %H:%M:%S} | {niveau} | {ip}:{port}/{proto} "
            f"| user={user} | {contenu}")


def evenement_normal(ts: datetime, rnd: random.Random) -> str:
    ip = rnd.choice(IPS_INTERNES if rnd.random() < 0.85 else
                    IPS_EXTERNES + BLACKLIST[:3])
    user = rnd.choice(UTILISATEURS)
    port, proto = rnd.choice(SERVICES)
    tirage = rnd.random()

    if tirage < 0.30:
        ok = rnd.random() < 0.88
        statut = "success" if ok else "failed"
        return ligne(ts, "INFO" if ok else "WARNING", ip, port, proto, user,
                     {"event": "login", "status": statut,
                      "code": 200 if ok else 401})
    if tirage < 0.65:
        code = rnd.choices([200, 201, 304, 404, 403, 500, 503],
                           [60, 5, 10, 10, 5, 7, 3])[0]
        niveau = ("INFO" if code < 400 else
                  "WARNING" if code < 500 else "ERROR")
        return ligne(ts, niveau, ip, 443, "TCP", user,
                     {"event": "http", "path": rnd.choice(CHEMINS),
                      "code": code})
    if tirage < 0.72:
        return ligne(ts, "INFO", ip, 80, "HTTP", "monitor",
                     {"event": "healthcheck"})
    if tirage < 0.74:
        return ligne(ts, "ERROR", ip, 443, "HTTP", user,
                     {"event": "http", "path": rnd.choice(INJECTIONS),
                      "code": 400})
    if tirage < 0.76:
        return ligne(ts, "CRITICAL", ip, port, proto, user,
                     {"event": "service", "name": rnd.choice(
                         ["postgres", "nginx", "auth"]), "code": 500,
                      "msg": "service down"})
    niveau = rnd.choices(["INFO", "WARNING", "ERROR"], [70, 20, 10])[0]
    return ligne(ts, niveau, ip, port, proto, user, rnd.choice(MESSAGES_BRUTS))


def rafale_force_brute(ts: datetime,
                       rnd: random.Random) -> tuple[list[str], datetime]:
    ip = rnd.choice(IPS_EXTERNES + BLACKLIST)
    cible = rnd.choice(["admin", "root", "alice", "svc_backup"])
    lignes = []
    for _ in range(rnd.randint(6, 25)):
        ts += timedelta(seconds=rnd.randint(1, 3))
        lignes.append(ligne(ts, "WARNING", ip, 22, "SSH", cible,
                            {"event": "login", "status": "failed",
                             "code": 401}))
    if rnd.random() < 0.3:  # parfois l'attaquant finit par trouver
        ts += timedelta(seconds=2)
        lignes.append(ligne(ts, "INFO", ip, 22, "SSH", cible,
                            {"event": "login", "status": "success",
                             "code": 200}))
    return lignes, ts


def lignes_cassees(rnd: random.Random) -> str:
    return rnd.choice([
        "",
        "# rotation du fichier",
        "2026-11-03 25:61:00 | INFO | 10.0.0.1:22/SSH | user=bob | test",
        "2026-11-03 10:00:00 | DEBUG | 10.0.0.1:22/SSH | user=bob | test",
        "2026-11-03 10:00:00 | ERROR | 300.12.1.1:22/SSH | user=bob | x",
        "2026-11-03 10:00:00 | ERROR | 10.0.0.1:22/SSH | user=bob | {cassé",
        "ligne totalement illisible",
        "2026-11-03 10:00:00 | INFO | 10.0.0.1:22/SSH | user=bob | ",
    ])


def generer_fichier(chemin: Path, nb_lignes: int, debut: datetime,
                    rnd: random.Random) -> datetime:
    ts = debut
    ecrites = 0
    with chemin.open("w", encoding="utf-8") as fichier:
        while ecrites < nb_lignes:
            # beaucoup moins de trafic la nuit, comme sur un vrai serveur
            nuit = ts.hour < 7 or ts.hour >= 21
            ts += timedelta(seconds=rnd.randint(8, 40) if nuit
                            else rnd.randint(2, 8))
            if rnd.random() < 0.0007:
                bloc, ts = rafale_force_brute(ts, rnd)
            elif rnd.random() < 0.01:
                bloc = [lignes_cassees(rnd)]
            else:
                bloc = [evenement_normal(ts, rnd)]
            fichier.write("\n".join(bloc) + "\n")
            ecrites += len(bloc)
    return ts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lignes", type=int, default=15000)
    parser.add_argument("--fichiers", type=int, default=3)
    parser.add_argument("--sortie", default="data")
    parser.add_argument("--graine", type=int, default=42)
    args = parser.parse_args()

    rnd = random.Random(args.graine)
    dossier = Path(args.sortie)
    dossier.mkdir(parents=True, exist_ok=True)

    debut = datetime(2026, 11, 3, 0, 0, 0)
    for numero in range(1, args.fichiers + 1):
        chemin = dossier / f"serveur_{numero:02d}.log"
        # chaque fichier reprend là où le précédent s'est arrêté
        # (comme une rotation de logs)
        debut = generer_fichier(chemin, args.lignes, debut, rnd)
        print(f"{chemin} : {args.lignes} lignes")

    with (dossier / "blacklist.txt").open("w", encoding="utf-8") as fichier:
        fichier.write("# IP bannies (une par ligne)\n")
        fichier.write("\n".join(BLACKLIST) + "\n")
    print(f"{dossier / 'blacklist.txt'} : {len(BLACKLIST)} IP")


if __name__ == "__main__":
    main()

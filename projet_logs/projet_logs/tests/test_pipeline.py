"""Tests unitaires (lancer avec : python -m unittest -v)."""

import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from log_engine.aggregation import agreger, comparer_ips
from log_engine.detection import detecter_force_brute
from log_engine.ingestion import flux_simule, lire_plusieurs_sources
from log_engine.parsing import parser_ligne, parser_source
from log_engine.regles import apply_security_rules, regle_niveau_critique
from log_engine.transformations import construire_pipeline, router

LIGNE_OK = ('2026-11-03 10:00:00 | ERROR | 10.0.0.1:22/SSH | user=Bob | '
            '{"event": "login", "status": "failed", "code": 401}')


class TestParsing(unittest.TestCase):

    def test_ligne_valide(self):
        record = parser_ligne(LIGNE_OK)
        self.assertIsNotNone(record)
        self.assertEqual(record["source"], ("10.0.0.1", 22, "SSH"))
        self.assertEqual(record["payload"]["code"], 401)

    def test_lignes_invalides(self):
        for ligne in ["", "n'importe quoi",
                      LIGNE_OK.replace("ERROR", "DEBUG"),
                      LIGNE_OK.replace("10.0.0.1", "300.0.0.1"),
                      LIGNE_OK.replace("10:00:00", "25:00:00")]:
            with self.subTest(ligne=ligne):
                self.assertIsNone(parser_ligne(ligne))

    def test_source_est_un_tuple(self):
        self.assertIsInstance(parser_source("1.2.3.4:80/http"), tuple)


class TestPipeline(unittest.TestCase):

    def test_filtrage_et_normalisation(self):
        lignes = ["", "# commentaire", LIGNE_OK, "ligne cassée",
                  LIGNE_OK.replace('{"event": "login", "status": "failed",'
                                   ' "code": 401}', "healthcheck ok")]
        resultat = list(construire_pipeline(flux_simule(lignes)))
        self.assertEqual(len(resultat), 1)
        self.assertEqual(resultat[0]["user"], "bob")

    def test_lecture_paresseuse(self):
        with tempfile.TemporaryDirectory() as dossier:
            f1, f2 = Path(dossier, "a.log"), Path(dossier, "b.log")
            f1.write_text("l1\nl2\n", encoding="utf-8")
            f2.write_text("l3\n", encoding="utf-8")
            gen = lire_plusieurs_sources([f1, Path(dossier, "absent"), f2])
            self.assertEqual(next(gen), "l1")
            self.assertEqual(list(gen), ["l2", "l3"])

    def test_routage(self):
        self.assertEqual(router({"level": "ERROR", "code": 500})[0], "erreur")
        self.assertEqual(router({"level": "INFO"})[0], "statut")
        self.assertEqual(router(("1.1.1.1", 22, "SSH"))[0],
                         "connexion_admin")
        self.assertEqual(router(("1.1.1.1", 443, "TCP"))[0], "connexion")
        self.assertEqual(router("texte libre")[0], "brut")
        self.assertEqual(router(42)[0], "inconnu")


class TestAgregation(unittest.TestCase):

    def test_ensembles(self):
        res = comparer_ips({"a", "b", "c"}, frozenset({"c", "d"}))
        self.assertEqual(res["intersection"], {"c"})
        self.assertEqual(res["difference_symetrique"], {"a", "b", "d"})
        self.assertIsInstance(res["union"], frozenset)

    def test_compteurs(self):
        stats = agreger(construire_pipeline(flux_simule([LIGNE_OK] * 3)))
        self.assertEqual(stats.par_niveau["ERROR"], 3)
        self.assertEqual(stats.par_niveau["CRITICAL"], 0)  # pas de KeyError


class TestForceBrute(unittest.TestCase):

    def setUp(self):
        self.t0 = datetime(2026, 1, 1, 12, 0, 0)

    def serie(self, nb, pas=2, succes_final=False):
        tentatives = [(self.t0 + timedelta(seconds=i * pas), False, "root")
                      for i in range(nb)]
        if succes_final:
            tentatives.append(
                (self.t0 + timedelta(seconds=nb * pas), True, "root"))
        return tentatives

    def test_attaque_detectee(self):
        alertes, complete = detecter_force_brute({"6.6.6.6": self.serie(8)})
        self.assertEqual(len(alertes), 1)
        self.assertTrue(complete)
        self.assertIn("en cours", alertes[0]["statut"])

    def test_succes_apres_echecs(self):
        alertes, _ = detecter_force_brute(
            {"6.6.6.6": self.serie(6, succes_final=True)})
        self.assertIn("SUCCES", alertes[0]["statut"])

    def test_sous_le_seuil(self):
        alertes, _ = detecter_force_brute({"1.1.1.1": self.serie(3)})
        self.assertEqual(alertes, [])

    def test_trop_lent_pour_la_fenetre(self):
        alertes, _ = detecter_force_brute({"1.1.1.1": self.serie(8, pas=30)})
        self.assertEqual(alertes, [])

    def test_arret_max_alertes(self):
        donnees = {"a": self.serie(6), "b": self.serie(6)}
        alertes, complete = detecter_force_brute(donnees, max_alertes=1)
        self.assertEqual(len(alertes), 1)
        self.assertFalse(complete)


class TestRegles(unittest.TestCase):

    def test_moteur(self):
        records = construire_pipeline(flux_simule(
            [LIGNE_OK, LIGNE_OK.replace("ERROR", "CRITICAL")]))
        res = apply_security_rules(
            regle_niveau_critique,
            lambda r, **kw: "bob vu" if r["user"] == "bob" else None,
            "pas une fonction",
            records=records,
        )
        self.assertEqual(res["regle_niveau_critique"]["total"], 1)
        self.assertEqual(res["<lambda>"]["total"], 2)

    def test_records_obligatoire(self):
        with self.assertRaises(ValueError):
            apply_security_rules(regle_niveau_critique)


if __name__ == "__main__":
    unittest.main()

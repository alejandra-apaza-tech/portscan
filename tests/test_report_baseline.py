import csv
import io
import json
import os
import tempfile
import unittest

from portscanner.baseline import find_violations, load_baseline
from portscanner.report import summarize, to_csv, to_json, to_text
from portscanner.scanner import PortResult

RESULTADOS = [
    PortResult("10.0.0.1", 22, "open", "ssh", 1.5),
    PortResult("10.0.0.1", 23, "open", "telnet", 2.0),
    PortResult("10.0.0.1", 80, "closed", "http"),
    PortResult("10.0.0.2", 443, "filtered", "https"),
]


class TestRelatorio(unittest.TestCase):
    def test_resumo(self):
        self.assertEqual(summarize(RESULTADOS), {"open": 2, "closed": 1, "filtered": 1})

    def test_texto_mostra_so_abertas_por_padrao(self):
        texto = to_text(RESULTADOS)
        self.assertIn("ssh", texto)
        self.assertNotIn("https", texto)
        self.assertIn("https", to_text(RESULTADOS, show_all=True))

    def test_json_valido(self):
        dados = json.loads(to_json(RESULTADOS, {"alvo": "10.0.0.0/24"}))
        self.assertEqual(dados["metadata"]["alvo"], "10.0.0.0/24")
        self.assertEqual(len(dados["resultados"]), 2)
        self.assertEqual(dados["resumo"]["open"], 2)

    def test_csv_valido(self):
        linhas = list(csv.reader(io.StringIO(to_csv(RESULTADOS))))
        self.assertEqual(linhas[0], ["host", "port", "state", "service", "rtt_ms"])
        self.assertEqual(len(linhas), 3)


class TestBaseline(unittest.TestCase):
    def test_violacoes(self):
        permitido = {"*": {22}, "10.0.0.2": {443}}
        self.assertEqual([v.port for v in find_violations(RESULTADOS, permitido)], [23])

    def test_leitura_do_arquivo(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "b.json")
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump({"allowed": {"*": [22, 443]}}, f)
            self.assertEqual(load_baseline(caminho), {"*": {22, 443}})

    def test_baseline_invalida(self):
        with tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "b.json")
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump({"allowed": {"*": ["22"]}}, f)
            with self.assertRaises(ValueError):
                load_baseline(caminho)
            with self.assertRaises(ValueError):
                load_baseline(os.path.join(pasta, "nao-existe.json"))


if __name__ == "__main__":
    unittest.main()

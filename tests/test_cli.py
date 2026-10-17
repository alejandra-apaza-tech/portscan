import asyncio
import contextlib
import io
import json
import os
import tempfile
import threading
import unittest

from portscanner.cli import main


@contextlib.contextmanager
def servidor_local():
    """Servidor TCP em outra thread, para a CLI (que usa asyncio.run) escanear de verdade."""
    pronto, parar, info = threading.Event(), threading.Event(), {}

    def rodar():
        async def principal():
            srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
            info["porta"] = srv.sockets[0].getsockname()[1]
            pronto.set()
            while not parar.is_set():
                await asyncio.sleep(0.05)
            srv.close()
            await srv.wait_closed()
        asyncio.run(principal())

    t = threading.Thread(target=rodar)
    t.start()
    pronto.wait(5)
    try:
        yield info["porta"]
    finally:
        parar.set()
        t.join()


def executar(*args):
    saida, erro = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(erro):
        codigo = main(list(args))
    return codigo, saida.getvalue(), erro.getvalue()


class TestCLI(unittest.TestCase):
    def test_alvo_publico_e_bloqueado(self):
        codigo, _, erro = executar("8.8.8.8", "-p", "80")
        self.assertEqual(codigo, 3)
        self.assertIn("--allow-public", erro)

    def test_porta_invalida(self):
        codigo, _, erro = executar("127.0.0.1", "-p", "99999")
        self.assertEqual(codigo, 3)
        self.assertIn("Erro", erro)

    def test_scan_json_encontra_porta_aberta(self):
        with servidor_local() as porta:
            codigo, saida, _ = executar("127.0.0.1", "-p", str(porta), "-f", "json", "-t", "2")
        self.assertEqual(codigo, 0)
        self.assertEqual(json.loads(saida)["resultados"][0]["port"], porta)

    def test_baseline_gera_codigo_1(self):
        with servidor_local() as porta, tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "b.json")
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump({"allowed": {"*": [22]}}, f)
            codigo, _, erro = executar("127.0.0.1", "-p", str(porta), "--baseline", caminho, "-t", "2")
        self.assertEqual(codigo, 1)
        self.assertIn("VIOLAÇÃO", erro)

    def test_baseline_permitida_gera_codigo_0(self):
        with servidor_local() as porta, tempfile.TemporaryDirectory() as pasta:
            caminho = os.path.join(pasta, "b.json")
            with open(caminho, "w", encoding="utf-8") as f:
                json.dump({"allowed": {"*": [porta]}}, f)
            codigo, _, _ = executar("127.0.0.1", "-p", str(porta), "--baseline", caminho, "-t", "2")
        self.assertEqual(codigo, 0)


if __name__ == "__main__":
    unittest.main()

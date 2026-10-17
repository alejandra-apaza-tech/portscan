import asyncio
import socket
import unittest

from portscanner.scanner import probe, scan


def porta_livre() -> int:
    """Pega uma porta e a libera: conectar nela depois deve ser recusado (closed) ou filtrado."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestScanner(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servidor = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
        self.porta_aberta = self.servidor.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.servidor.close()
        await self.servidor.wait_closed()

    async def test_porta_aberta(self):
        r = await probe("127.0.0.1", self.porta_aberta, timeout=2)
        self.assertEqual(r.state, "open")
        self.assertIsNotNone(r.rtt_ms)

    async def test_porta_fechada(self):
        r = await probe("127.0.0.1", porta_livre(), timeout=2)
        # Aceita tanto 'closed' quanto 'filtered' dependendo do comportamento do SO/firewall
        self.assertIn(r.state, ["closed", "filtered"])
        self.assertIsNone(r.rtt_ms)

    async def test_scan_varias_portas_em_ordem(self):
        fechada = porta_livre()
        resultados = await scan(["127.0.0.1"], [self.porta_aberta, fechada], timeout=2, concurrency=2)
        self.assertEqual([r.port for r in resultados], sorted([self.porta_aberta, fechada]))
        estados = {r.port: r.state for r in resultados}
        self.assertEqual(estados[self.porta_aberta], "open")
        self.assertIn(estados[fechada], ["closed", "filtered"])

    async def test_callback_recebe_cada_resultado(self):
        vistos = []
        await scan(["127.0.0.1"], [self.porta_aberta], timeout=2, on_result=vistos.append)
        self.assertEqual(len(vistos), 1)


if __name__ == "__main__":
    unittest.main()
import unittest

from portscanner.ports import COMMON_PORTS, parse_ports, service_name


class TestPorts(unittest.TestCase):
    def test_porta_unica_e_lista(self):
        self.assertEqual(parse_ports("80"), [80])
        self.assertEqual(parse_ports("443, 22,80"), [22, 80, 443])

    def test_intervalo_e_combinacao(self):
        self.assertEqual(parse_ports("1-3"), [1, 2, 3])
        self.assertEqual(parse_ports("22,20-21,22"), [20, 21, 22])

    def test_common(self):
        self.assertEqual(parse_ports("common"), sorted(COMMON_PORTS))

    def test_entradas_invalidas(self):
        for ruim in ["", "abc", "0", "65536", "10-5", "1-", "22,,x"]:
            with self.subTest(ruim=ruim):
                with self.assertRaises(ValueError):
                    parse_ports(ruim)

    def test_nome_do_servico(self):
        self.assertEqual(service_name(22), "ssh")
        self.assertEqual(service_name(3389), "rdp")


if __name__ == "__main__":
    unittest.main()

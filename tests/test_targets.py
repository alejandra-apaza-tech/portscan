import unittest

from portscanner.targets import expand_targets, is_private, require_authorization, resolve_host


class TestTargets(unittest.TestCase):
    def test_ip_unico(self):
        self.assertEqual(expand_targets("127.0.0.1"), ["127.0.0.1"])
        self.assertEqual(resolve_host("10.1.2.3"), "10.1.2.3")

    def test_cidr(self):
        self.assertEqual(expand_targets("192.168.0.0/30"), ["192.168.0.1", "192.168.0.2"])
        self.assertEqual(expand_targets("10.0.0.5/32"), ["10.0.0.5"])

    def test_cidr_grande_demais(self):
        with self.assertRaises(ValueError):
            expand_targets("10.0.0.0/16")

    def test_entradas_invalidas(self):
        for ruim in ["", "300.1.1.1/24", "::1", "2001:db8::/32"]:
            with self.subTest(ruim=ruim):
                with self.assertRaises(ValueError):
                    expand_targets(ruim)

    def test_privado_e_publico(self):
        self.assertTrue(is_private("192.168.1.10"))
        self.assertTrue(is_private("127.0.0.1"))
        self.assertFalse(is_private("8.8.8.8"))

    def test_trava_de_autorizacao(self):
        require_authorization(["192.168.0.1", "10.0.0.1"])           # privados passam
        with self.assertRaises(PermissionError):
            require_authorization(["8.8.8.8"])                        # público bloqueia
        require_authorization(["8.8.8.8"], allow_public=True)         # com confirmação passa


if __name__ == "__main__":
    unittest.main()

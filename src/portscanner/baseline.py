"""Política de portas permitidas: o que estiver aberto fora da lista é uma violação."""
import json

from .scanner import PortResult


def load_baseline(caminho: str) -> dict[str, set[int]]:
    """Formato: {"allowed": {"*": [22, 443], "192.168.0.10": [80]}}  ('*' vale para qualquer host)."""
    try:
        with open(caminho, encoding="utf-8") as arquivo:
            dados = json.load(arquivo)
    except (OSError, json.JSONDecodeError) as erro:
        raise ValueError(f"Não foi possível ler a baseline '{caminho}': {erro}") from erro
    permitido = dados.get("allowed") if isinstance(dados, dict) else None
    if not isinstance(permitido, dict):
        raise ValueError("A baseline precisa ter a chave 'allowed' com um objeto.")
    saida: dict[str, set[int]] = {}
    for host, portas in permitido.items():
        if not isinstance(portas, list) or not all(isinstance(p, int) for p in portas):
            raise ValueError(f"'allowed.{host}' deve ser uma lista de números de porta.")
        saida[host] = set(portas)
    return saida


def find_violations(results: list[PortResult], allowed: dict[str, set[int]]) -> list[PortResult]:
    violacoes = []
    for r in results:
        if r.state != "open":
            continue
        permitidas = allowed.get("*", set()) | allowed.get(r.host, set())
        if r.port not in permitidas:
            violacoes.append(r)
    return violacoes

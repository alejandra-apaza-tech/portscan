"""Geração de relatórios em texto, JSON e CSV."""
import csv
import io
import json
from collections import Counter

from . import __version__
from .scanner import PortResult


def summarize(results: list[PortResult]) -> dict:
    contagem = Counter(r.state for r in results)
    return {estado: contagem.get(estado, 0) for estado in ("open", "closed", "filtered")}


def _visiveis(results: list[PortResult], show_all: bool) -> list[PortResult]:
    return results if show_all else [r for r in results if r.state == "open"]


def to_text(results: list[PortResult], show_all: bool = False) -> str:
    linhas = [f"{'HOST':<16}{'PORTA':<8}{'ESTADO':<10}{'SERVIÇO':<14}RTT"]
    for r in _visiveis(results, show_all):
        rtt = f"{r.rtt_ms} ms" if r.rtt_ms is not None else "-"
        linhas.append(f"{r.host:<16}{r.port:<8}{r.state:<10}{r.service:<14}{rtt}")
    if len(linhas) == 1:
        linhas.append("(nenhuma porta aberta encontrada)")
    resumo = summarize(results)
    linhas.append(f"\nResumo: {resumo['open']} aberta(s), {resumo['closed']} fechada(s), {resumo['filtered']} filtrada(s)")
    return "\n".join(linhas)


def to_json(results: list[PortResult], metadata: dict, show_all: bool = False) -> str:
    corpo = {
        "metadata": {"ferramenta": "portscan", "versao": __version__, **metadata},
        "resumo": summarize(results),
        "resultados": [r.to_dict() for r in _visiveis(results, show_all)],
    }
    return json.dumps(corpo, indent=2, ensure_ascii=False)


def to_csv(results: list[PortResult], show_all: bool = False) -> str:
    saida = io.StringIO()
    escritor = csv.writer(saida, lineterminator="\n")
    escritor.writerow(["host", "port", "state", "service", "rtt_ms"])
    for r in _visiveis(results, show_all):
        escritor.writerow([r.host, r.port, r.state, r.service, "" if r.rtt_ms is None else r.rtt_ms])
    return saida.getvalue()

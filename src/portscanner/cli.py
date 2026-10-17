"""Interface de linha de comando.

Códigos de saída: 0 = ok | 1 = violação da baseline | 2 = uso incorreto | 3 = erro/autorização.
"""
import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone

from . import __version__
from .baseline import find_violations, load_baseline
from .ports import parse_ports
from .report import to_csv, to_json, to_text
from .scanner import scan
from .targets import expand_targets, require_authorization

MAX_PROBES = 100_000
AVISO = ("[!] Use somente em sistemas que você administra ou tem autorização por escrito para testar.\n"
         "    O scan completa conexões TCP e pode aparecer em logs e sistemas de detecção de intrusão.")


def _intervalo(minimo: float, maximo: float, tipo=float):
    def validar(texto: str):
        valor = tipo(texto)
        if not minimo <= valor <= maximo:
            raise argparse.ArgumentTypeError(f"deve estar entre {minimo} e {maximo}")
        return valor
    return validar


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="portscan", description="Scanner de portas TCP para auditoria de redes autorizadas.")
    p.add_argument("target", help="host, IP ou faixa CIDR (ex.: 192.168.0.0/24)")
    p.add_argument("-p", "--ports", default="common", help="'common', '22,80,443', '1-1024' ou combinações (padrão: common)")
    p.add_argument("-t", "--timeout", type=_intervalo(0.1, 30), default=1.0, help="segundos por conexão (padrão: 1.0)")
    p.add_argument("-c", "--concurrency", type=_intervalo(1, 1000, int), default=200, help="conexões simultâneas (padrão: 200)")
    p.add_argument("-f", "--format", choices=["text", "json", "csv"], default="text", help="formato do relatório")
    p.add_argument("-o", "--output", help="salva o relatório neste arquivo em vez de imprimir")
    p.add_argument("--baseline", help="arquivo JSON com as portas permitidas; viola = código de saída 1")
    p.add_argument("--show-all", action="store_true", help="inclui portas fechadas e filtradas no relatório")
    p.add_argument("--max-hosts", type=int, default=256, help="máximo de hosts em uma faixa CIDR (padrão: 256)")
    p.add_argument("--allow-public", action="store_true", help="permite alvos públicos (confirma que você tem autorização)")
    p.add_argument("--version", action="version", version=f"portscan {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        portas = parse_ports(args.ports)
        hosts = expand_targets(args.target, args.max_hosts)
        require_authorization(hosts, args.allow_public)
        if len(hosts) * len(portas) > MAX_PROBES:
            raise ValueError(f"Muitas combinações host/porta (máximo {MAX_PROBES}). Reduza a faixa.")
        permitido = load_baseline(args.baseline) if args.baseline else None
    except (ValueError, PermissionError) as erro:
        print(f"Erro: {erro}", file=sys.stderr)
        return 3

    print(AVISO, file=sys.stderr)
    inicio = time.perf_counter()
    resultados = asyncio.run(scan(hosts, portas, timeout=args.timeout, concurrency=args.concurrency))
    metadata = {
        "alvo": args.target, "hosts": len(hosts), "portas_testadas": len(portas),
        "iniciado_em": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duracao_s": round(time.perf_counter() - inicio, 2),
    }

    if args.format == "json":
        relatorio = to_json(resultados, metadata, args.show_all)
    elif args.format == "csv":
        relatorio = to_csv(resultados, args.show_all)
    else:
        relatorio = to_text(resultados, args.show_all)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as arquivo:
            arquivo.write(relatorio)
        print(f"Relatório salvo em {args.output}", file=sys.stderr)
    else:
        print(relatorio)

    if permitido is not None:
        violacoes = find_violations(resultados, permitido)
        for v in violacoes:
            print(f"VIOLAÇÃO: {v.host}:{v.port} ({v.service}) está aberta e não consta na baseline", file=sys.stderr)
        if violacoes:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

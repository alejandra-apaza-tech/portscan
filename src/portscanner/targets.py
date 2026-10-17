"""Resolução de alvos e travas de uso responsável."""
import ipaddress
import socket


def resolve_host(alvo: str) -> str:
    """Devolve um IPv4 a partir de um IP ou de um nome de host."""
    try:
        ip = ipaddress.ip_address(alvo)
        if ip.version != 4:
            raise ValueError("Apenas IPv4 é suportado nesta versão.")
        return str(ip)
    except ValueError as erro:
        if "IPv4" in str(erro):
            raise
    try:
        return socket.gethostbyname(alvo)
    except socket.gaierror as erro:
        raise ValueError(f"Não foi possível resolver '{alvo}'.") from erro


def expand_targets(spec: str, max_hosts: int = 256) -> list[str]:
    """Aceita um host/IP ou uma faixa CIDR (ex.: 192.168.0.0/24)."""
    spec = spec.strip()
    if not spec:
        raise ValueError("Alvo vazio.")
    if "/" not in spec:
        return [resolve_host(spec)]
    try:
        rede = ipaddress.ip_network(spec, strict=False)
    except ValueError as erro:
        raise ValueError(f"Faixa CIDR inválida: '{spec}'") from erro
    if rede.version != 4:
        raise ValueError("Apenas IPv4 é suportado nesta versão.")
    hosts = [str(h) for h in rede.hosts()] or [str(rede.network_address)]
    if len(hosts) > max_hosts:
        raise ValueError(f"A faixa tem {len(hosts)} hosts; o limite é {max_hosts} (use --max-hosts).")
    return hosts


def is_private(ip: str) -> bool:
    endereco = ipaddress.ip_address(ip)
    return endereco.is_private or endereco.is_loopback or endereco.is_link_local


def require_authorization(hosts: list[str], allow_public: bool = False) -> None:
    """Bloqueia alvos públicos, a menos que o operador confirme que tem autorização."""
    publicos = [h for h in hosts if not is_private(h)]
    if publicos and not allow_public:
        exemplo = ", ".join(publicos[:3])
        raise PermissionError(
            f"Alvo público detectado ({exemplo}). Escanear sistemas sem autorização é ilegal. "
            "Se você tem permissão por escrito, repita o comando com --allow-public."
        )

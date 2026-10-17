"""Interpretação da lista de portas e nomes de serviços."""
import socket

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb", 993: "imaps",
    995: "pop3s", 1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


def parse_ports(spec: str) -> list[int]:
    """Aceita 'common', '80', '22,80,443', '1-1024' ou combinações ('22,8000-8100')."""
    ports: set[int] = set()
    for parte in spec.replace(" ", "").split(","):
        if not parte:
            continue
        if parte.lower() == "common":
            ports.update(COMMON_PORTS)
        elif "-" in parte:
            ini, _, fim = parte.partition("-")
            if not (ini.isdigit() and fim.isdigit()):
                raise ValueError(f"Intervalo de portas inválido: '{parte}'")
            a, b = int(ini), int(fim)
            if a > b:
                raise ValueError(f"Intervalo invertido: '{parte}'")
            ports.update(_validar(p) for p in range(a, b + 1))
        elif parte.isdigit():
            ports.add(_validar(int(parte)))
        else:
            raise ValueError(f"Porta inválida: '{parte}'")
    if not ports:
        raise ValueError("Nenhuma porta informada.")
    return sorted(ports)


def _validar(porta: int) -> int:
    if not 1 <= porta <= 65535:
        raise ValueError(f"Porta fora do intervalo 1-65535: {porta}")
    return porta


def service_name(porta: int) -> str:
    if porta in SERVICES:
        return SERVICES[porta]
    try:
        return socket.getservbyport(porta, "tcp")
    except OSError:
        return "desconhecido"

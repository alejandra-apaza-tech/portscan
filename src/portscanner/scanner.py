"""Núcleo do scanner: TCP connect assíncrono com limite de concorrência."""
import asyncio
import ipaddress
import time
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from .ports import service_name


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    state: str                      # 'open' | 'closed' | 'filtered'
    service: str
    rtt_ms: Optional[float] = None

    def to_dict(self) -> dict:
        return asdict(self)


async def probe(host: str, port: int, timeout: float = 1.0) -> PortResult:
    """Tenta conectar. open = conectou; closed = recusou (RST); filtered = sem resposta/erro de rede."""
    inicio = time.perf_counter()
    nome = service_name(port)
    try:
        _, escritor = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except ConnectionRefusedError:
        return PortResult(host, port, "closed", nome)
    except (asyncio.TimeoutError, OSError):
        return PortResult(host, port, "filtered", nome)
    rtt = round((time.perf_counter() - inicio) * 1000, 2)
    escritor.close()
    try:
        await escritor.wait_closed()
    except OSError:
        pass
    return PortResult(host, port, "open", nome, rtt)


async def scan(hosts: list[str], ports: list[int], timeout: float = 1.0, concurrency: int = 200,
               on_result: Optional[Callable[[PortResult], None]] = None) -> list[PortResult]:
    """Varre todos os pares host/porta, no máximo `concurrency` conexões ao mesmo tempo."""
    limite = asyncio.Semaphore(concurrency)

    async def trabalhar(host: str, porta: int) -> PortResult:
        async with limite:
            resultado = await probe(host, porta, timeout)
        if on_result:
            on_result(resultado)
        return resultado

    resultados = await asyncio.gather(*(trabalhar(h, p) for h in hosts for p in ports))
    return sorted(resultados, key=lambda r: (int(ipaddress.ip_address(r.host)), r.port))

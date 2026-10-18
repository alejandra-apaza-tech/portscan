# PortScan

Scanner de portas TCP **assíncrono**, feito em Python, para **auditar quais serviços estão expostos**
nos equipamentos de uma rede que você administra. Sem dependências externas.

> **Uso responsável:** escaneie somente sistemas seus ou com **autorização por escrito**.
> Varrer redes de terceiros pode ser crime. Por padrão, a ferramenta **recusa alvos públicos**.

## Para que serve (caso de uso em empresa)

Todo serviço aberto é uma porta de entrada em potencial. O PortScan responde duas perguntas:

1. **O que está aberto hoje?** (ex.: servidor com RDP e banco de dados expostos)
2. **Isso é o esperado?** Com uma *baseline* (lista de portas permitidas), qualquer porta aberta
   fora da lista é uma violação e o programa termina com código de saída `1`. Isso permite rodar
   o scan agendado (cron, pipeline de CI) e disparar um alerta quando algo mudar.

## Instalação

```bash
<<<<<<< HEAD
git clone https://github.com/alejandra-apaza-tech/portscan.git
=======
https://github.com/alejandra-apaza-tech/portscan.git
cd portscan
>>>>>>> 0cdcd924a8bb2c9cf6b5ad87ee925b9530665d1e
pip install -e .          # requer Python 3.10+
```

## Uso

```bash
portscan 192.168.0.10                         # portas mais comuns (padrão)
portscan 192.168.0.10 -p 1-1024               # intervalo
portscan 192.168.0.10 -p 22,80,443,8000-8100  # lista combinada
portscan 192.168.0.0/24 -f csv -o rede.csv    # rede inteira, relatório em CSV
portscan 192.168.0.10 -f json -o relatorio.json
portscan 192.168.0.0/24 --baseline baseline.example.json   # auditoria contra a política
```

Exemplo de saída:

```
HOST            PORTA   ESTADO    SERVIÇO       RTT
192.168.0.10    22      open      ssh           0.62 ms
192.168.0.10    3389    open      rdp           0.91 ms

Resumo: 2 aberta(s), 21 fechada(s), 0 filtrada(s)
```

| Opção | Descrição |
|---|---|
| `-p, --ports` | `common`, `22,80`, `1-1024` ou combinações |
| `-t, --timeout` | segundos por conexão (0,1 a 30; padrão 1) |
| `-c, --concurrency` | conexões simultâneas (1 a 1000; padrão 200) |
| `-f, --format` | `text`, `json` ou `csv` |
| `-o, --output` | grava o relatório em arquivo |
| `--baseline` | JSON com portas permitidas (`{"allowed": {"*": [22, 443]}}`) |
| `--show-all` | mostra também portas fechadas e filtradas |
| `--max-hosts` | limite de hosts numa faixa CIDR (padrão 256) |
| `--allow-public` | permite alvos públicos (você confirma que tem autorização) |

**Códigos de saída:** `0` ok · `1` violação da baseline · `2` uso incorreto · `3` erro ou alvo não autorizado.

## Como funciona

É um scan **TCP connect**: o programa tenta completar a conexão em cada porta.

- **open**: a conexão foi aceita.
- **closed**: o host respondeu recusando (RST).
- **filtered**: sem resposta no tempo limite (geralmente firewall).

O `asyncio` permite centenas de tentativas ao mesmo tempo com uma única thread, e um
`Semaphore` limita a concorrência para não sobrecarregar a rede.

## Arquitetura

| Módulo | Responsabilidade |
|---|---|
| `ports.py` | interpretar a lista de portas e nomes de serviço |
| `targets.py` | resolver alvos/CIDR e as travas de autorização |
| `scanner.py` | núcleo assíncrono (`probe` e `scan`) |
| `report.py` | relatórios texto/JSON/CSV |
| `baseline.py` | política de portas permitidas |
| `cli.py` | argumentos, códigos de saída e orquestração |

## Testes

```bash
python -m unittest discover -s tests -v    # 27 testes, sem dependências
```

Os testes de scan usam **servidores reais em 127.0.0.1**, nada é escaneado fora da sua máquina.
O GitHub Actions roda a suíte em Python 3.10, 3.11 e 3.12.

## Limitações

- Apenas TCP e IPv4 (sem UDP, sem SYN scan, sem detecção de sistema operacional).
- O scan completa a conexão, então **aparece em logs** e pode acionar sistemas de detecção de intrusão.
- "filtered" pode ser firewall, mas também perda de pacotes: aumente `--timeout` se suspeitar.
- Para auditorias profissionais completas, use também ferramentas consolidadas como o Nmap.

## Roadmap

- [ ] Suporte a IPv6 e UDP
- [ ] Captura de banner (versão do serviço) com opção explícita
- [ ] Relatório em HTML e comparação entre dois scans (o que mudou)
- [ ] Limite de taxa (pacotes por segundo)
- [ ] Publicação no PyPI

## Licença

MIT. Troque `SEU NOME` no `LICENSE`.

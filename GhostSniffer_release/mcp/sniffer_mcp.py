#!/usr/bin/env python3
# sniffer_mcp.py — MCP (stdio) que deixa o Claude Code consultar o PangyaSniffer AO VIVO.
#
# Casca FINA de proposito: o app (PangyaSniffer.exe) e o dono do dado -- ele ja tem tudo em RAM COM
# o decode do ground truth e serve por uma 2a porta (9932, comando texto -> JSON por linha). Este
# script so traduz tool-call MCP <-> comando na 9932. Zero dependencia (stdlib), pra rodar em
# qualquer python sem pip install.
#
# Fluxo que ele destrava: em vez de "user copia log -> me manda -> eu leio", o Claude pergunta
# direto no meio do teste. sniffer_wait = "reconecta agora que eu vejo acontecer"; sniffer_diff =
# a jogada que resolveu o reconnect (o que uma sessao viu e a outra nao), agora numa tool call.
import datetime
import json
import os
import socket
import sys

try:
    import decoders  # decode automatico de struct (mesma pasta); opcional
except ImportError:
    decoders = None

HOST = "127.0.0.1"
QUERY_PORT = 9932

CAPTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")


def talk(cmd: str, read_timeout: float = 20.0):
    """Manda 1 comando texto pra 9932 e le 1 linha JSON de volta."""
    try:
        s = socket.create_connection((HOST, QUERY_PORT), timeout=3.0)
    except OSError:
        return {
            "error": "nao consegui falar com o PangyaSniffer na porta 9932 -- o app esta aberto? "
            "(abre o PangyaSniffer.exe; ele que escuta)"
        }
    try:
        s.settimeout(read_timeout)
        s.sendall((cmd + "\n").encode("utf-8"))
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n", 1)[0]
        try:
            return json.loads(line.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            return {"error": "resposta invalida do app", "raw": line.decode("utf-8", "replace")}
    except socket.timeout:
        return {"error": "timeout esperando resposta do app"}
    finally:
        s.close()


# ----------------------------------------------------------------------- tools

def _bool_arg(a, k):
    return bool(a.get(k, False))


def t_status(a):
    return talk("status")


def t_sessions(a):
    return talk("sessions")


def t_query(a):
    parts = ["query"]
    if a.get("uid") is not None:
        parts.append(f"uid={int(a['uid'])}")
    if a.get("opcode"):
        parts.append(f"op={str(a['opcode']).replace('0x','').replace('0X','')}")
    if a.get("dir"):
        parts.append(f"dir={a['dir']}")
    if a.get("name"):
        parts.append(f"name={a['name']}")
    if a.get("src"):
        parts.append(f"src={a['src']}")
    if _bool_arg(a, "hide_noisy"):
        parts.append("noisy=hide")
    if a.get("since") is not None:
        parts.append(f"since={int(a['since'])}")
    if a.get("ate") is not None:
        parts.append(f"ate={int(a['ate'])}")
    parts.append(f"limit={int(a.get('limit', 50))}")
    return talk(" ".join(parts))


def _maybe_decode(pkt):
    """Anexa 'decoded' (campos nomeados) se ha um decoder de struct pro (opcode,dir)."""
    if not decoders or not isinstance(pkt, dict) or "op" not in pkt:
        return pkt
    try:
        op = int(pkt["op"], 16)
    except (ValueError, TypeError):
        return pkt
    d = decoders.decode(op, pkt.get("dir"), pkt.get("hex", ""))
    if d:
        pkt["decoded"] = d
    return pkt


def t_packet(a):
    cmd = f"packet seq={int(a['seq'])}"
    if a.get("max_bytes") is not None:
        cmd += f" max={int(a['max_bytes'])}"
    p = _maybe_decode(talk(cmd))
    # Vista "so texto": os pedacos legiveis do payload, sem o hex.
    # ⚠️ E heuristica: um NUMERO cujos bytes caem na faixa ASCII aparece como texto (ex.: o uid
    # 14646 = 0x3936 vira "69" e faz a conta "teste" parecer "teste69"). Pacote e struct binaria,
    # nao texto -- quem da a verdade e o `decoded`.
    if decoders and isinstance(p, dict) and p.get("hex"):
        try:
            p["texto_legivel"] = decoders.strings_do_pacote(bytes.fromhex(p["hex"]))
        except ValueError:
            pass
    return p


def t_diff(a):
    cmd = f"diff a={int(a['uidA'])} b={int(a['uidB'])}"
    if a.get("dir"):
        cmd += f" dir={a['dir']}"
    if _bool_arg(a, "hide_noisy"):
        cmd += " noisy=hide"
    if a.get("since") is not None:
        cmd += f" since={int(a['since'])}"
    return talk(cmd)


def t_wait(a):
    parts = ["wait"]
    if a.get("opcode"):
        parts.append(f"op={str(a['opcode']).replace('0x','').replace('0X','')}")
    if a.get("uid") is not None:
        parts.append(f"uid={int(a['uid'])}")
    if a.get("dir"):
        parts.append(f"dir={a['dir']}")
    if a.get("name"):
        parts.append(f"name={a['name']}")
    timeout_ms = int(a.get("timeout_ms", 15000))
    parts.append(f"timeout={timeout_ms}")
    # o socket tem que esperar mais que o wait do lado C++, senao corta antes
    r = talk(" ".join(parts), read_timeout=timeout_ms / 1000.0 + 5.0)
    if isinstance(r, dict) and r.get("packet"):
        r["packet"] = _maybe_decode(r["packet"])
    return r


# ---------------------------------------------------------------- timeline
# O ESQUELETO DA PARTIDA. Nasceu porque eu reconstrui essa mesma visao na mao ~5x durante a
# caca ao late-join: filtrar o diluvio e mostrar so os eventos ESTRUTURAIS na ordem.
# dir importa: varios opcodes sao BIDIRECIONAIS com significados diferentes (0x63 in=coordenada /
# out=changeTurn; 0x65 in=booster / out=fim de hole; 0x48 in=load% / out=roomlist).
_EVENTOS = {
    (0x08, "in"): "CRIA SALA",
    (0x09, "in"): "entra na sala",
    (0x0E, "in"): ">>> COMECA JOGO",
    (0x9D, "in"): ">>> LATE-JOIN (EnterGameAfterStarted)",
    (0x76, "out"): "roster (sendInitialData)",
    (0x52, "out"): "course (Game::sendInitialData)",
    (0x1A, "in"): "--- INIT HOLE",
    (0x11, "in"): "finish load hole",
    (0x34, "in"): "char intro OK (= PRONTO p/ jogar)",
    (0x22, "in"): "start turn time",
    (0x12, "in"): "*** TACADA (Init Shot)",
    (0x15, "in"): "[power shot]",
    (0x65, "in"): "[booster]",
    (0x185, "in"): "[assist green]",
    (0x1B, "in"): "sync shot (bola parou)",
    (0x1C, "in"): "finish shot",
    (0x55, "out"): "server repassa a tacada",
    (0x64, "out"): "POSICAO DA BOLA (sendSyncShot)",
    (0x63, "out"): "<<< CHANGE TURN >>>",
    (0x53, "out"): "<<< COMECA O HOLE (0x53) >>>",
    (0x31, "in"): "FINISH HOLE DATA (placar)",
    (0x65, "out"): "=== FIM DO HOLE (updateFinishHole)",
    (0x6D, "out"): "=== updateFinishHole",
    (0x06, "in"): "### FINISH GAME",
    (0x130, "in"): "### EXIT PRACTICE",
    (0x8B, "out"): "!! pause/deletePlayer (0x8B)",
    (0x8A, "out"): "!!! KICK (server deu shutdown no socket)",
    (0x33, "in"): "!!! EXCEPTION DO CLIENTE (leia com sniffer_packet!)",
    (0x7E, "out"): "!! kickPlayerRoom",
}


def t_timeline(a):
    parts = ["query", f"limit={int(a.get('limit', 500))}"]
    if a.get("uid") is not None:
        parts.append(f"uid={int(a['uid'])}")
    if a.get("since") is not None:
        parts.append(f"since={int(a['since'])}")
    d = talk(" ".join(parts), read_timeout=20.0)
    if isinstance(d, dict) and "error" in d:
        return d

    nicks = _mapa_contas()
    linhas = []
    for p in d.get("packets", []):
        try:
            op = int(p["op"], 16)
        except (ValueError, TypeError):
            continue
        ev = _EVENTOS.get((op, p["dir"]))
        if not ev:
            continue
        linha = {"seq": p["seq"], "time": p["time"], "dir": p["dir"],
                 "uid": p["uid"], "quem": nicks.get(p["uid"], str(p["uid"])),
                 "op": p["op"], "len": p["len"], "evento": ev}
        if decoders and decoders.has_decoder(op, p["dir"]) and op == 0x33:
            dec = decoders.decode(op, p["dir"], p.get("hex", ""))
            if dec:  # o 0x33 e curto: ja traz a mensagem do cliente aqui
                linha["decoded"] = dec
        linhas.append(linha)

    return {"total_no_periodo": d.get("total"), "eventos": len(linhas),
            "dica": "opcodes bidirecionais tem significado diferente por dir (0x63/0x65/0x48). "
                    "Use sniffer_packet num seq p/ o hex+campos.",
            "timeline": linhas}


def _mapa_contas():
    """UID -> conta, lido dos pacotes de Login (0x02) da propria captura."""
    if not decoders:
        return {}
    try:
        d = talk("query op=02 dir=in limit=50")
        m = {}
        for p in d.get("packets", []):
            dec = decoders.decode(0x02, "in", p.get("hex", ""))
            if not dec:
                continue
            campos = {c["campo"]: c["valor"] for c in dec.get("campos", [])}
            uid, conta = campos.get("uid"), campos.get("id (conta)")
            if uid and conta:
                m[uid] = conta
        return m
    except Exception:
        return {}


# ---------------------------------------------------------------- compare (auditoria de broadcast)
# O `sniffer_diff` compara CONTAGEM por sessao => so acha pacote FALTANDO. Ele e CEGO pro caso pior:
# o pacote chegou nos dois mas com bytes DIFERENTES (as contagens batem e ele fica quieto). Esse e o
# desync silencioso -- e foi exatamente o bug do [[versus-reconnect]]: o 0x76 do late-joiner CHEGAVA,
# mas com o roster errado.
# Aqui a unidade e a RAJADA: o server manda o mesmo opcode pros N players no mesmo instante
# (ex.: seq 631/632/633 = um 0x64 pros 3 no mesmo ms). Pra cada rajada respondemos 2 perguntas:
#   1) FALTOU pra alguem?      2) chegou DIFERENTE pra alguem?
def t_compare(a):
    parts = ["query", "dir=out", f"limit={int(a.get('limit', 500))}"]
    if a.get("opcode"):
        parts.append(f"op={str(a['opcode']).replace('0x','').replace('0X','')}")
    if a.get("since") is not None:
        parts.append(f"since={int(a['since'])}")
    if a.get("ate") is not None:
        parts.append(f"ate={int(a['ate'])}")
    d = talk(" ".join(parts), read_timeout=25.0)
    if isinstance(d, dict) and "error" in d:
        return d

    nicks = _mapa_contas()

    # Janela de vida de cada sessao: so cobramos um broadcast de quem JA ESTAVA e AINDA ESTAVA online
    # naquele instante (senao a 1a versao acusava "Ken nao recebeu" em pacotes de antes dele logar).
    janela = {}
    for s in (talk("sessions").get("sessions") or []):
        if s.get("uid"):  # uid 0 = handshake, nao e player
            janela[s["uid"]] = (s["first"], s["last"])

    # agrupa a rajada por (opcode, instante)
    rajadas = {}
    for p in d.get("packets", []):
        k = (p["op"], p["time"])
        rajadas.setdefault(k, []).append(p)

    achados, ok, unicast = [], 0, 0
    for (op, tempo), pkts in sorted(rajadas.items(), key=lambda kv: kv[1][0]["seq"]):
        uids = {p["uid"] for p in pkts}

        # 1 destinatario = UNICAST por design (login, catch-up, resposta pessoal). Nao e broadcast:
        # nao ha nada a auditar. Sem isso a tool afoga em falso positivo.
        if len(uids) < 2:
            unicast += 1
            continue

        # esperado = quem estava online NAQUELE instante (comparacao de string HH:MM:SS.mmm funciona)
        esperados = {u for u, (ini, fim) in janela.items() if ini <= tempo <= fim}
        faltou = esperados - uids

        # Sub-agrupa por CONTEUDO: o server manda varios pacotes DIFERENTES do mesmo opcode no mesmo
        # ms (ex.: 0x115 = 3 tabelas de rate; 0xA3 = a % de cada player). Entao "conteudos diferentes"
        # NAO e erro por si so -- e so mostrado. So o "nao recebeu NADA" e inequivoco e vira flag.
        por_conteudo = {}
        for p in pkts:
            por_conteudo.setdefault((p["len"], p["hex"]), []).append(p["uid"])

        if not faltou:
            ok += 1
            if not a.get("mostrar_tudo"):
                continue

        item = {"seq": pkts[0]["seq"], "time": tempo, "op": op, "name": pkts[0]["name"],
                "recebeu": [nicks.get(u, str(u)) for u in sorted(uids)],
                "conteudos": [{"len": ln, "hex_inicio": hx,
                               "para": [nicks.get(u, str(u)) for u in sorted(us)]}
                              for (ln, hx), us in por_conteudo.items()]}
        if faltou:
            item["!! NAO RECEBEU"] = [nicks.get(u, str(u)) for u in sorted(faltou)]
        achados.append(item)

    return {"players": {str(u): nicks.get(u, str(u)) for u in sorted(janela)},
            "broadcasts_analisados": len(rajadas) - unicast, "broadcasts_ok": ok,
            "unicast_ignorados": unicast, "com_flag_nao_recebeu": len(achados),
            "legenda": "So audita RAJADA com 2+ destinatarios (1 = unicast por design: login/catch-up). "
                       "FLAG unico e inequivoco: '!! NAO RECEBEU' = alguem online nao recebeu NADA da "
                       "rajada (foi assim que um 0x63 pulou o late-joiner). O campo 'conteudos' mostra os "
                       "payloads distintos e p/ quem foram -- conteudo diferente NAO e erro por si so "
                       "(0xA3 e a % de cada um; 0x115 sao tabelas distintas), quem julga e voce. "
                       "Use opcode= p/ focar (ex. 0x76 roster, 0x63 turno) e mostrar_tudo=true p/ ver os OK.",
            "achados": achados[:60]}


# ---------------------------------------------------------------- rastro da bola (p/ o reconnect mid-hole)
# Usa o decoder do 0x64 (ShotSyncData = oid + x/y/z + estado). Serve a TAREFA 2: "onde estava a bola
# de cada um quando ele caiu?" e "o server restaurou a posicao no reconnect?".
def t_balls(a):
    parts = ["query", "op=64", "dir=out", f"limit={int(a.get('limit', 300))}"]
    if a.get("since") is not None:
        parts.append(f"since={int(a['since'])}")
    if a.get("ate") is not None:
        parts.append(f"ate={int(a['ate'])}")
    d = talk(" ".join(parts), read_timeout=20.0)
    if isinstance(d, dict) and "error" in d:
        return d
    if not decoders:
        return {"error": "decoders.py nao carregou"}

    nicks = _mapa_contas()
    vistos, rastro = set(), []
    for p in d.get("packets", []):
        # o 0x64 e broadcast: o MESMO evento vai pros N players. Conta uma vez so (por seq/time+oid).
        dec = decoders.decode(0x64, "out", p.get("hex", ""))
        if not dec or "campos" not in dec:
            continue
        c = {x["campo"]: x for x in dec["campos"]}
        oid = c.get("oid (de quem e a bola)", {}).get("valor")
        chave = (p["time"], oid)
        if chave in vistos:
            continue
        vistos.add(chave)
        rastro.append({
            "seq": p["seq"], "time": p["time"], "oid_da_bola": oid,
            "X": c.get("location.X", {}).get("valor"),
            "Y": c.get("location.Y", {}).get("valor"),
            "Z": c.get("location.Z", {}).get("valor"),
            "estado": c.get("state", {}).get("nota"),
            "pang": c.get("pang", {}).get("valor"),
        })

    return {"eventos": len(rastro),
            "nota": "0x64 = VersusBase::sendSyncShot = onde a bola de cada OID assentou (broadcast). "
                    "E o pacote-chave da TAREFA 2 (reconnect mid-hole): o server ja sabe a posicao.",
            "obs_oid": "oid != uid. Veja sniffer_timeline/sessions p/ casar. " + json.dumps(nicks),
            "rastro": rastro}


def t_stats(a):
    parts = ["stats"]
    if a.get("uid") is not None:
        parts.append(f"uid={int(a['uid'])}")
    if a.get("dir"):
        parts.append(f"dir={a['dir']}")
    if _bool_arg(a, "hide_noisy"):
        parts.append("noisy=hide")
    return talk(" ".join(parts))


def t_export(a):
    # puxa o dump com hex COMPLETO e grava num arquivo que o Claude le direto (analise offline).
    parts = ["dump", f"limit={int(a.get('limit', 5000))}"]
    if a.get("uid") is not None:
        parts.append(f"uid={int(a['uid'])}")
    if a.get("dir"):
        parts.append(f"dir={a['dir']}")
    if _bool_arg(a, "hide_noisy"):
        parts.append("noisy=hide")
    data = talk(" ".join(parts), read_timeout=30.0)
    if isinstance(data, dict) and "error" in data:
        return data
    try:
        os.makedirs(CAPTURES_DIR, exist_ok=True)
        name = a.get("name") or ("capture_" +
                                  datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
        if not name.endswith(".json"):
            name += ".json"
        path = os.path.join(CAPTURES_DIR, os.path.basename(name))  # basename: sem escapar a pasta
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        return {"ok": True, "file": path,
                "packets": len(data.get("packets", [])), "total": data.get("total")}
    except OSError as e:
        return {"error": f"falha ao gravar: {e}"}


_DIR_ENUM = {"type": "string", "enum": ["in", "out", "both"],
             "description": "in = client->server, out = server->client, both = ambos (padrao)"}

TOOLS = [
    {
        "name": "sniffer_status",
        "description": "Estado do sniffer AO VIVO: fontes (servers) conectadas, total de pacotes, "
        "sessoes, DROPS (pacotes perdidos -- se >0 a captura nao esta integra), bytes, se bateu o "
        "teto de memoria. Chame primeiro pra saber se ha trafego chegando.",
        "handler": t_status,
        "schema": {"type": "object", "properties": {}},
    },
    {
        "name": "sniffer_sessions",
        "description": "Lista as sessoes (cada UID de player visto) com contagem de pacotes e "
        "janela de tempo. Use pra achar os UIDs antes de query/diff.",
        "handler": t_sessions,
        "schema": {"type": "object", "properties": {}},
    },
    {
        "name": "sniffer_query",
        "description": "Lista pacotes capturados (mais recentes primeiro no fim da lista), com "
        "opcode + NOME do ground truth (fonte do server) + len + inicio do hex. Filtros combinaveis. "
        "Retorna preview do hex (32 bytes); use sniffer_packet pro hex completo de um seq.",
        "handler": t_query,
        "schema": {
            "type": "object",
            "properties": {
                "uid": {"type": "integer", "description": "so os pacotes deste UID de player"},
                "opcode": {"type": "string", "description": "opcode em hex, ex '76' ou '0x113'"},
                "dir": _DIR_ENUM,
                "name": {"type": "string", "description": "substring do nome (ground truth), ex 'sendInitialData'"},
                "src": {"type": "string", "description": "server fonte: Game/Auth/Login/Message/GGAuth"},
                "hide_noisy": {"type": "boolean", "description": "esconde o diluvio de sync de tacada"},
                "since": {"type": "integer", "description": "so pacotes com seq MAIOR que este"},
                "ate": {"type": "integer", "description": "TETO de seq. Com since forma a janela [since+1, ate] -- use SEMPRE que quiser um trecho especifico, senao `limit` devolve a CAUDA da captura e nao o trecho"},
                "limit": {"type": "integer", "description": "quantos retornar (padrao 50, max 500). Devolve os ULTIMOS que casam"},
            },
        },
    },
    {
        "name": "sniffer_packet",
        "description": "Um pacote pelo seq, com hex COMPLETO (capado por max_bytes) + a funcao do "
        "server que o montou (fonte). Use depois de achar o seq num sniffer_query.",
        "handler": t_packet,
        "schema": {
            "type": "object",
            "properties": {
                "seq": {"type": "integer", "description": "o numero # do pacote (coluna seq)"},
                "max_bytes": {"type": "integer", "description": "teto de bytes do hex (padrao 4096, max 65536)"},
            },
            "required": ["seq"],
        },
    },
    {
        "name": "sniffer_diff",
        "description": "A JOGADA MATADORA: compara duas sessoes (2 clients) e mostra os opcodes que "
        "uma recebeu/mandou e a outra NAO (ou em contagem diferente). E o metodo que resolveu o bug "
        "do reconnect versus 2x -- achar o pacote que faltava. onlyIn: 'A'=so na A, 'B'=so na B.",
        "handler": t_diff,
        "schema": {
            "type": "object",
            "properties": {
                "uidA": {"type": "integer"},
                "uidB": {"type": "integer"},
                "dir": _DIR_ENUM,
                "hide_noisy": {"type": "boolean"},
                "since": {"type": "integer", "description": "so compara pacotes com seq MAIOR que este (janela) -- essencial quando as 2 sessoes tem historicos diferentes"},
            },
            "required": ["uidA", "uidB"],
        },
    },
    {
        "name": "sniffer_wait",
        "description": "BLOQUEIA ate um pacote NOVO casar o filtro (ou timeout). E o 'faz a acao "
        "agora que eu vejo acontecer': chame, peca pro user reconectar/tacar, e volta o pacote no "
        "instante que chega. Retorna o pacote com hex completo, ou matched=false no timeout.",
        "handler": t_wait,
        "schema": {
            "type": "object",
            "properties": {
                "opcode": {"type": "string", "description": "opcode em hex a esperar"},
                "uid": {"type": "integer"},
                "dir": _DIR_ENUM,
                "name": {"type": "string", "description": "substring do nome a esperar"},
                "timeout_ms": {"type": "integer", "description": "espera max em ms (padrao 15000, max 120000)"},
            },
        },
    },
    {
        "name": "sniffer_timeline",
        "description": "O ESQUELETO DA PARTIDA: so os eventos ESTRUTURAIS na ordem (cria sala, comeca "
        "jogo, LATE-JOIN, init hole, char intro, TACADAS, CHANGE TURN, posicao da bola, fim de hole, "
        "finish game, EXCEPTIONS e KICKS), com o nick de cada UID e o 0x33 (crash do cliente) ja "
        "decodificado. **E a PRIMEIRA tool a chamar quando algo deu errado numa partida** -- mostra "
        "onde o fluxo parou sem afogar no diluvio de sync.",
        "handler": t_timeline,
        "schema": {
            "type": "object",
            "properties": {
                "uid": {"type": "integer", "description": "so este player"},
                "since": {"type": "integer", "description": "so depois deste seq"},
                "limit": {"type": "integer", "description": "pacotes a varrer (padrao 500)"},
            },
        },
    },
    {
        "name": "sniffer_compare",
        "description": "AUDITORIA DE BROADCAST: pra cada rajada (o server manda o mesmo opcode pros N "
        "players no mesmo instante) responde 2 perguntas: (1) FALTOU pra alguem? (2) chegou com bytes "
        "DIFERENTES pra alguem? ⚠️ O sniffer_diff NAO pega o caso (2) -- ele compara CONTAGEM, entao um "
        "pacote que chega nos dois com conteudo diferente passa batido. Foi exatamente o bug do roster "
        "(0x76) no versus-reconnect. Use p/ validar que todos veem a MESMA partida.",
        "handler": t_compare,
        "schema": {
            "type": "object",
            "properties": {
                "opcode": {"type": "string", "description": "so este opcode (hex) -- RECOMENDADO (ex. '76' roster, '63' turno). Omita p/ varrer tudo"},
                "since": {"type": "integer"},
                "ate": {"type": "integer", "description": "teto de seq (janela)"},
                "limit": {"type": "integer", "description": "pacotes a varrer (padrao 500)"},
                "mostrar_tudo": {"type": "boolean", "description": "mostra tambem as rajadas OK (com os conteudos p/ voce comparar), nao so as com flag"},
            },
        },
    },
    {
        "name": "sniffer_balls",
        "description": "RASTRO DA BOLA: decodifica os 0x64 (sendSyncShot = ShotSyncData) e mostra onde a "
        "bola de cada OID assentou (x/y/z + estado PLAYABLE_AREA/INTO_HOLE/OUT_OF_BOUNDS + pang), em "
        "ordem. E a ferramenta da TAREFA 2 (reconnect MID-HOLE): mostra a posicao que o server ja "
        "conhece e permite conferir se ela foi restaurada depois do reconnect.",
        "handler": t_balls,
        "schema": {
            "type": "object",
            "properties": {
                "since": {"type": "integer"},
                "ate": {"type": "integer"},
                "limit": {"type": "integer", "description": "pacotes a varrer (padrao 300)"},
            },
        },
    },
    {
        "name": "sniffer_stats",
        "description": "PERFIL DE TRAFEGO num relance: histograma (dir,opcode) -> contagem + bytes, "
        "do maior pro menor, com o nome do ground truth. E a 1a pergunta ao olhar uma captura: 'o "
        "que esta dominando?'. Use hide_noisy pra tirar sync de tacada + heartbeat.",
        "handler": t_stats,
        "schema": {
            "type": "object",
            "properties": {
                "uid": {"type": "integer", "description": "so este UID"},
                "dir": _DIR_ENUM,
                "hide_noisy": {"type": "boolean", "description": "esconde sync de tacada + heartbeat TTL"},
            },
        },
    },
    {
        "name": "sniffer_export",
        "description": "Salva a captura atual (hex COMPLETO) num arquivo JSON em PangyaSniffer/"
        "captures/ e retorna o caminho, pra analise offline sem re-perguntar pacote a pacote. Filtra "
        "por uid/dir/hide_noisy. Depois de exportar, LEIA o arquivo retornado.",
        "handler": t_export,
        "schema": {
            "type": "object",
            "properties": {
                "uid": {"type": "integer", "description": "so este UID"},
                "dir": _DIR_ENUM,
                "hide_noisy": {"type": "boolean"},
                "limit": {"type": "integer", "description": "max de pacotes (padrao 5000, os mais recentes)"},
                "name": {"type": "string", "description": "nome do arquivo (opcional; padrao capture_<timestamp>.json)"},
            },
        },
    },
]

_BY_NAME = {t["name"]: t for t in TOOLS}


# ----------------------------------------------------------------------- protocolo MCP (stdio JSON-RPC)

def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def reply(rid, result):
    send({"jsonrpc": "2.0", "id": rid, "result": result})


def reply_err(rid, code, message):
    send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def handle(msg):
    method = msg.get("method")
    rid = msg.get("id")

    if method == "initialize":
        # ecoa a versao que o cliente pediu (negociacao); cai num padrao conhecido se faltar
        pv = msg.get("params", {}).get("protocolVersion", "2025-06-18")
        reply(rid, {
            "protocolVersion": pv,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "pangya-sniffer", "version": "1.0.0"},
        })
    elif method == "notifications/initialized":
        pass  # notificacao, sem resposta
    elif method == "tools/list":
        reply(rid, {"tools": [
            {"name": t["name"], "description": t["description"], "inputSchema": t["schema"]}
            for t in TOOLS
        ]})
    elif method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        tool = _BY_NAME.get(name)
        if not tool:
            reply_err(rid, -32602, f"tool desconhecida: {name}")
            return
        try:
            data = tool["handler"](args)
        except Exception as e:  # nunca derruba o MCP por causa de 1 call
            data = {"error": f"falha na tool: {e}"}
        text = json.dumps(data, ensure_ascii=False, indent=2)
        is_err = isinstance(data, dict) and "error" in data
        reply(rid, {"content": [{"type": "text", "text": text}], "isError": is_err})
    elif rid is not None:
        reply_err(rid, -32601, f"metodo nao suportado: {method}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            handle(msg)
        except Exception as e:
            if isinstance(msg, dict) and msg.get("id") is not None:
                reply_err(msg["id"], -32603, f"erro interno: {e}")


if __name__ == "__main__":
    main()

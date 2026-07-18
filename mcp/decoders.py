# decoders.py — decode automatico de struct: transforma o hex cru em CAMPOS NOMEADOS.
#
# E o salto de "sniffer que mostra hex" pra "sniffer que mostra o SIGNIFICADO". Cada decoder le o
# payload de um opcode conhecido do jeito que o SERVER le (ground truth: a struct + a ordem de
# readXxx do handler) e devolve uma lista de {campo, valor}. Fica na camada python de proposito:
# adicionar um decoder novo NAO exige rebuild do app -- so editar aqui.
#
# Registrar um decoder = por a funcao no dict DECODERS por (opcode, dir). dir: "in"=client->server,
# "out"=server->client, None=qualquer.
import struct


def _f(b, o):
    return round(struct.unpack_from("<f", b, o)[0], 4)


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _i32(b, o):
    return struct.unpack_from("<i", b, o)[0]


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


# ---------------------------------------------------------------------------- 0x12 Init Shot
# Ground truth: struct ShotDataBase (Game Server/TYPE/game_type.hpp) lido em
# Approach::requestInitShot (approach.cpp:497). Layout PACKED, validado contra tacada real.
#   u16 opcode | u16 option (0=normal / 1=power shot, +9B power_shot) | ShotDataBase(58B packed)
_SPECIAL_BITS = ["spin_front", "spin_back", "curve_left", "curve_right", "tomahawk", "cobra", "spike"]


def decode_init_shot(b):
    out = []
    option = _u16(b, 2)
    # VALIDADO por teste controlado (2026-07-17): option=1 <=> jogador usou POWER SHOT
    # (0->1 ao ativar). Quando =1 vem o bloco PowerShot de 9B com o bonus de potencia.
    out.append({"campo": "option (u16)", "valor": option,
                "nota": "POWER SHOT ativo" if option == 1 else "tacada normal (sem power shot)"})
    base = 4
    if option == 1:
        # PowerShot { u8 option; i32 decrease_power_shot; i32 increase_power_shot } = 9B @ offset 4
        out.append({"campo": "power_shot.option", "valor": b[4]})
        out.append({"campo": "power_shot.decrease (bonus-)", "valor": _i32(b, 5)})
        out.append({"campo": "power_shot.increase (bonus+ potencia)", "valor": _i32(b, 9)})
        base = 13  # ShotDataBase vem depois dos 9 bytes
    if len(b) < base + 58:
        out.append({"campo": "_erro", "valor": "payload curto p/ ShotDataBase"})
        return out

    special = _u32(b, base + 17)
    ativos = [name for i, name in enumerate(_SPECIAL_BITS) if special & (1 << i)]

    out += [
        {"campo": "forca (bar_point[0])", "valor": _f(b, base + 0)},
        {"campo": "impact/hitPangya (bar_point[1])", "valor": _f(b, base + 4)},
        {"campo": "spin_X lateral (ball_effect[0])", "valor": _f(b, base + 8)},
        {"campo": "spin_Y back/top (ball_effect[1])", "valor": _f(b, base + 12)},
        {"campo": "acerto_pangya_flag", "valor": b[base + 16]},
        {"campo": "special_shot", "valor": "0x%08X" % special, "ativos": ativos or ["nenhum"]},
        {"campo": "time_hole_sync", "valor": _u32(b, base + 21)},
        {"campo": "mira (aim R)", "valor": _f(b, base + 25)},
        {"campo": "time_shot", "valor": _u32(b, base + 29)},
        {"campo": "bar_point1 (start)", "valor": _f(b, base + 33)},
        {"campo": "club", "valor": b[base + 37]},
        {"campo": "fUnknown[0]", "valor": _f(b, base + 38)},
        {"campo": "fUnknown[1]", "valor": _f(b, base + 42)},
        {"campo": "impact_zone_pixel", "valor": _f(b, base + 46)},
        {"campo": "natural_wind_X", "valor": _i32(b, base + 50)},
        {"campo": "natural_wind_Y", "valor": _i32(b, base + 54)},
    ]
    return out


# ------------------------------------------------- 0x1B / 0x64 Sync Shot = POSICAO DA BOLA
# Ground truth: struct ShotSyncData (game_type.hpp:232). 0x1B = client->server (o cliente reporta
# onde a bola parou), 0x64 = VersusBase::sendSyncShot = server->client (BROADCAST pros dois).
#
# 🔑 ESTE E O PACOTE QUE CARREGA A POSICAO DA BOLA (x,y,z) + de QUEM (oid) + o ESTADO. A nota antiga
# do [[versus-reconnect]] dizia "nao existe pacote 'sua bola esta em (x,z)'" -- REFUTADO por captura
# real (2026-07-17): dá pra ver a bola andando pelo hole ate INTO_HOLE. E o candidato #1 pra
# restaurar a bola no reconnect mid-hole (o server ja tem `pgi->location`).
_SHOT_STATE = {2: "PLAYABLE_AREA", 3: "OUT_OF_BOUNDS", 4: "INTO_HOLE", 5: "UNPLAYABLE_AREA"}


def decode_sync_shot(b):
    if len(b) < 29:
        return [{"campo": "_erro", "valor": "payload curto p/ ShotSyncData"}]
    st = b[18]
    return [
        {"campo": "oid (de quem e a bola)", "valor": _u32(b, 2)},
        {"campo": "location.X", "valor": _f(b, 6)},
        {"campo": "location.Y", "valor": _f(b, 10)},
        {"campo": "location.Z", "valor": _f(b, 14)},
        {"campo": "state", "valor": st, "nota": _SHOT_STATE.get(st, "?")},
        {"campo": "bunker_flag", "valor": b[19]},
        {"campo": "ucUnknown", "valor": b[20]},
        {"campo": "pang", "valor": _u32(b, 21)},
        {"campo": "bonus_pang", "valor": _u32(b, 25)},
        {"campo": "_resto (state_shot/tempo/penalidade)", "valor": b[29:].hex()},
    ]


# ------------------------------------------------- helpers de string do protocolo
# `packet::readString()` do server = u16 tamanho + os bytes. NAO e zero-terminada.
def _rstr(b, o):
    """Le uma string do protocolo em `o`. Devolve (texto, proximo_offset)."""
    n = _u16(b, o)
    s = b[o + 2:o + 2 + n].decode("latin-1", "replace")
    return s, o + 2 + n


def strings_do_pacote(b, minimo=4):
    """Extrai so os pedacos LEGIVEIS do payload (tipo o `strings` do unix).
    E o 'modo limpo': serve p/ olhar/compartilhar um pacote sem o hex. ATENCAO: e uma
    HEURISTICA -- um numero cujos bytes caem na faixa ASCII aparece como se fosse texto
    (foi assim que o uid 14646 (0x3936) virou o "69" de um falso nick "teste69")."""
    out, cur = [], []
    for x in b:
        if 32 <= x < 127:
            cur.append(chr(x))
        else:
            if len(cur) >= minimo:
                out.append("".join(cur))
            cur = []
    if len(cur) >= minimo:
        out.append("".join(cur))
    return out


# ------------------------------------------------- 0x02 Login (client->server)
# Ground truth: game_server::requestLogin — readString(id), readInt32(uid), readInt32(ntKey),
# readUint16(command), readString(authKey), readString(version), readInt32(packet_version).
# 🔑 Este decoder tambem da o mapa UID -> CONTA de graca (o sniffer passa a rotular as sessoes).
def decode_login(b):
    out = []
    try:
        o = 2
        conta, o = _rstr(b, o)
        out.append({"campo": "id (conta)", "valor": conta})
        out.append({"campo": "uid", "valor": _u32(b, o)}); o += 4
        out.append({"campo": "ntKey", "valor": _u32(b, o)}); o += 4
        out.append({"campo": "command", "valor": "0x%04X" % _u16(b, o)}); o += 2
        authkey, o = _rstr(b, o)
        out.append({"campo": "authKey", "valor": authkey})
        ver, o = _rstr(b, o)
        out.append({"campo": "version (cliente)", "valor": ver})
        if o + 4 <= len(b):
            out.append({"campo": "packet_version", "valor": _u32(b, o)})
        out.append({"campo": "_resto (texto legivel)", "valor": strings_do_pacote(b[o:])})
    except Exception as e:
        out.append({"campo": "_erro", "valor": str(e)})
    return out


# ------------------------------------------------- 0x33 EXCEPTION = O ORACULO 🏆
# Ground truth: game_server::requestExceptionClientMessage — readUint8(tipo) + readString(msg).
# O CLIENTE REPORTA O PROPRIO CRASH EM TEXTO antes de morrer. Foi o que resolveu o late-join:
#   "DoToDefaultCamera(...) / PM_NET_NEXT_TURN(101917812) / ET(20031) / TO(-0.038788)"
#   = estado da maquina do cliente + ET = ha quantos ms ele esta preso nele.
# SEMPRE ler isto antes de teorizar (`sniffer_query opcode=33`).
def decode_exception(b):
    out = []
    try:
        tipo = b[2]
        msg, _ = _rstr(b, 3)
        out.append({"campo": "tipo", "valor": tipo})
        out.append({"campo": "MENSAGEM DO CLIENTE", "valor": msg})
        # o formato costuma ser "ESTADO(tick) / ESTADO(tick) / ET(ms) / TO(x)"
        for parte in [p.strip() for p in msg.split("/")]:
            if parte.startswith("ET("):
                out.append({"campo": ">>> preso ha (ms)", "valor": parte[3:].rstrip(")"),
                            "nota": "Elapsed Time no estado = ha quanto tempo o cliente espera"})
            elif parte.startswith("PM_"):
                out.append({"campo": ">>> estado do cliente", "valor": parte,
                            "nota": "a maquina de estados em que ele travou"})
    except Exception as e:
        out.append({"campo": "_erro", "valor": str(e)})
    return out


# ---------------------------------------------------------------------------- registro

# chave = (opcode, dir) ; dir None = qualquer sentido
DECODERS = {
    (0x12, "in"): ("ShotData (Init Shot)", decode_init_shot),
    (0x1B, "in"): ("ShotSyncData (Sync Shot: POSICAO DA BOLA)", decode_sync_shot),
    (0x64, "out"): ("ShotSyncData (sendSyncShot: POSICAO DA BOLA)", decode_sync_shot),
    (0x02, "in"): ("Login (id/uid/version)", decode_login),
    (0x33, "in"): ("EXCEPTION do cliente (o ORACULO de crash)", decode_exception),
}


def decode(op, dir_, hexstr):
    """Retorna {'struct':nome, 'campos':[...]} se ha decoder, senao None."""
    fn = DECODERS.get((op, dir_)) or DECODERS.get((op, None))
    if not fn:
        return None
    try:
        b = bytes.fromhex(hexstr)
    except ValueError:
        return None
    nome, f = fn
    try:
        return {"struct": nome, "campos": f(b)}
    except Exception as e:  # decoder nunca derruba o chamador
        return {"struct": nome, "erro": str(e)}


def has_decoder(op, dir_):
    return (op, dir_) in DECODERS or (op, None) in DECODERS

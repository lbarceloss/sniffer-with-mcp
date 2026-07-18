# -*- coding: utf-8 -*-
"""
Gera src/opcodes_gen.h a partir do FONTE DO SERVER.

Esse e o pulo do gato do projeto: um sniffer de fora DEDUZ o protocolo (e chuta os nomes).
Nos somos o server -- entao a gente nao deduz nada, a gente LE a verdade:

  ENTRADA (client->server): game_server.cpp tem a tabela real
        packet_func::funcs.addPacketCall(0x02, packet_func::packet002, this);
     e packet_func_sv.h tem o nome semantico:
        static int packet002(void* _arg1, void* _arg2);   // Login
     => 0x02 = "Login" (packet002). Nao e palpite: e o despacho que roda.

  SAIDA (server->client): nao ha tabela, mas ha algo melhor -- quem MONTA o pacote:
        void VersusBase::makeGameDataInit(packet& p) { ... p.init_plain((unsigned short)0x76);
     => 0x76 = "VersusBase::makeGameDataInit". O nome vem da funcao que criou os bytes.

Reexecutavel: rode de novo quando o server mudar.
"""
import io
import os
import re
import sys
from collections import OrderedDict

# Caminho do "Server Lib" do SEU servidor. Passe por argumento:
#     python gen_opcodes.py "C:\caminho\pro\seu\SuperSS-Dev\Server Lib"
# ou pela variavel de ambiente GHOST_SERVER_LIB. Sem nenhum dos dois, usa o default abaixo.
SRV = (sys.argv[1] if len(sys.argv) > 1
       else os.environ.get("GHOST_SERVER_LIB",
                           r"C:\Users\lbarc\Desktop\Abrir Map Completo\SuperSS-Dev\Server Lib"))
if not os.path.isdir(SRV):
    sys.exit("[gen_opcodes] Server Lib nao encontrado: %r\n"
             "  passe o caminho: python gen_opcodes.py \"<...>\\SuperSS-Dev\\Server Lib\"" % SRV)
GAME = os.path.join(SRV, "Game Server")
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "opcodes_gen.h")


def read(p):
    with io.open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


# ---------- ENTRADA: opcode -> packetNNN -> comentario ----------
def parse_in():
    gs = read(os.path.join(GAME, "Game Server", "game_server.cpp"))
    hdr = read(os.path.join(GAME, "PACKET", "packet_func_sv.h"))

    # static int packet002(void* _arg1, void* _arg2);	// Login
    nomes = {}
    for m in re.finditer(r"static\s+int\s+(packet[0-9A-Fa-f]+)\s*\([^)]*\)\s*;\s*(?://\s*(.*))?", hdr):
        fn, cmt = m.group(1), (m.group(2) or "").strip()
        cmt = re.sub(r"\s+", " ", cmt).strip(" /*")
        if cmt:
            nomes[fn] = cmt

    # funcs.addPacketCall(0x02, packet_func::packet002, this);
    #
    # SO a tabela `funcs` (cliente). NAO a `funcs_sv` (o "Server (Retorno)", dispatch pos-envio):
    # as duas registram o MESMO opcode, e a entrada _sv (packet_svFazNada, sem nome) vem DEPOIS no
    # arquivo => sobrescreveria o handler real do cliente e zeraria o nome. (Mesma raiz do bug de
    # captura dupla no tap: funcs vs funcs_sv.) `funcs\.` nao casa `funcs_sv.` porque exige o ponto.
    out = OrderedDict()
    for m in re.finditer(r"\bfuncs\.addPacketCall\(\s*(0x[0-9A-Fa-f]+|\d+)\s*,\s*packet_func::(\w+)", gs):
        op = int(m.group(1), 0)
        fn = m.group(2)
        # sem comentario semantico no header? cai no nome do handler (melhor que vazio na lista).
        out[op] = (nomes.get(fn) or fn, fn)
    return out


# ---------- SAIDA: opcode -> funcao que monta ----------
FUNC_RE = re.compile(r"^[A-Za-z_][\w\s:*&<>,]*?\b(\w+)::(\w+)\s*\(")
OPC_RE = re.compile(r"(?:init_plain|init_maked)\s*\(\s*\(unsigned short\)\s*(0x[0-9A-Fa-f]+|\d+)"
                    r"|packet\s+\w+\s*\(\s*\(unsigned short\)\s*(0x[0-9A-Fa-f]+|\d+)")


def parse_out():
    out = {}
    for root, _dirs, files in os.walk(GAME):
        if "Release" in root or "Debug" in root:
            continue
        for fn in files:
            if not fn.endswith(".cpp"):
                continue
            cur = "?"
            for ln in read(os.path.join(root, fn)).splitlines():
                fm = FUNC_RE.match(ln)
                if fm:
                    cur = "%s::%s" % (fm.group(1), fm.group(2))
                for m in OPC_RE.finditer(ln):
                    op = int(m.group(1) or m.group(2), 0)
                    out.setdefault(op, [])
                    if cur not in out[op]:
                        out[op].append(cur)
    return OrderedDict(sorted(out.items()))


def esc(s):
    return s.replace("\\", "\\\\").replace('"', '\\"')


def main():
    ins, outs = parse_in(), parse_out()

    L = []
    L.append("// GERADO por tools/gen_opcodes.py -- NAO EDITAR NA MAO.")
    L.append("// Nomes extraidos do FONTE DO SERVER = ground truth (nao e deducao de sniffer).")
    L.append("#pragma once")
    L.append("#include <stdint.h>")
    L.append("")
    L.append("struct OpcodeName { uint16_t op; const char* nome; const char* fonte; };")
    L.append("")
    L.append("// client -> server : tabela addPacketCall() do game_server.cpp (o despacho REAL)")
    L.append("static const OpcodeName kOpIn[] = {")
    for op, (cmt, fn) in sorted(ins.items()):
        L.append('    { 0x%04X, "%s", "%s" },' % (op, esc(cmt), esc(fn)))
    L.append("};")
    L.append("")
    L.append("// server -> client : funcao que MONTA o pacote (init_plain do opcode)")
    L.append("static const OpcodeName kOpOut[] = {")
    for op, fns in outs.items():
        nome = fns[0] if len(fns) == 1 else fns[0] + (" (+%d)" % (len(fns) - 1))
        L.append('    { 0x%04X, "%s", "%s" },' % (op, esc(nome), esc(" | ".join(fns[:6]))))
    L.append("};")
    L.append("")
    L.append("inline const char* opName(uint16_t op, bool in) {")
    L.append("    const OpcodeName* t = in ? kOpIn : kOpOut;")
    L.append("    size_t n = in ? sizeof(kOpIn)/sizeof(kOpIn[0]) : sizeof(kOpOut)/sizeof(kOpOut[0]);")
    L.append("    for (size_t i = 0; i < n; i++) if (t[i].op == op) return t[i].nome;")
    L.append('    return "";')
    L.append("}")
    L.append("")
    L.append("inline const char* opFonte(uint16_t op, bool in) {")
    L.append("    const OpcodeName* t = in ? kOpIn : kOpOut;")
    L.append("    size_t n = in ? sizeof(kOpIn)/sizeof(kOpIn[0]) : sizeof(kOpOut)/sizeof(kOpOut[0]);")
    L.append("    for (size_t i = 0; i < n; i++) if (t[i].op == op) return t[i].fonte;")
    L.append('    return "";')
    L.append("}")
    L.append("")

    with io.open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L))

    print("ENTRADA (client->server): %d opcodes" % len(ins))
    print("SAIDA   (server->client): %d opcodes" % len(outs))
    print("-> %s" % OUT)
    for op in (0x76, 0x113, 0x48, 0x9D, 0x53):
        if op in outs:
            print("   0x%02X out = %s" % (op, outs[op][:3]))


if __name__ == "__main__":
    main()

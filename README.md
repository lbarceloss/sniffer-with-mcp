Eu sempre achei que criar um MCP era algo extremamente complicado. Até que ontem resolvi sentar, estudar e descobrir como ele realmente funciona.

No fim das contas, existe uma biblioteca Python chamada mcp que faz praticamente todo o trabalho pesado.

Para testar, peguei como base um projeto qualquer da internet, adaptei quase tudo e montei meu primeiro MCP para usar aqui. Foi muito mais simples do que eu imaginava.

# Ghost Sniffer

**A plaintext PangYa packet sniffer, written by the server owner — from *inside* the server.**

by [hkfirewall.com](https://www.hkfirewall.com)

---

The community consensus is that sniffing PangYa is impossible. **They're right — from the outside.** From outside you'd have to beat Themida + GameGuard + the crypto, and *still* guess the protocol on the wire (that's the ceiling of the Adalink sniffer).

Ghost Sniffer flips the problem. **We are the process that creates the plaintext.** The bytes already exist in our RAM, by construction, before the key ever touches them. It isn't a harder version of their problem — it's a different problem, and it's easy.

The result: **100% of the bytes, both directions, no decryption, no heuristics**, validated by the game itself — and with the *truth* attached (the `uid`/`oid`/`opcode` the server already knew).

<!-- Drop a screenshot at docs/screenshot.png and uncomment:
![Ghost Sniffer](docs/screenshot.png)
-->

---

## Architecture

```
   ┌────────────────┐   plaintext frames (TCP 9931)    ┌──────────────────┐
   │  Game Server   │  ─────────────────────────────►  │  Ghost Sniffer   │
   │  (the TAP)     │   the APP listens, taps connect  │  (ImGui / DX11)  │
   └────────────────┘                                  └──────────────────┘
        connects out                                    listens :9931 (taps)
                                                        listens :9932 (query)
                                                                  │
                                                        ┌─────────▼─────────┐
                                                        │  MCP (Python)     │
                                                        │  Claude queries   │
                                                        │  the live capture │
                                                        └───────────────────┘
```

- **The app listens; the taps connect** (fan-in). Deliberately inverted: you can open/close the app anytime without touching the server, N sources drop in on their own, and "another client opened → new tab" falls out for free (the tab comes from the UID in the frame, not from config).
- **Two ports:** `9931` for the taps (the plaintext feed), `9932` for the query protocol (a dumb one-line-command → one-line-JSON server that the MCP layer speaks to).

---

## Server-side setup (what you modify to use it)

Everything lives at the **crypto boundary**: the plaintext is born inside the server; you tap it right before the key is applied (out) and right after it's removed (in).

### 1. Drop in the tap header

`pkt_tap.h` is **header-only on purpose** — the `.vcxproj` files list every `.cpp` individually (335 entries in the Game Server), so a new `.cpp` would mean editing every server's build. Copy it somewhere shared and `#include` it.

The tap is a lock-guarded ring buffer drained by its own thread. **Golden rule: never disturb the game.** Zero I/O on the send path, `memcpy` into a 32 MB ring under a tiny lock, socket work happens on the drain thread. App closed → cost is one flag read. Ring full → it drops the *whole* packet (never half) and **counts** it, and the count rides in every frame so the app always knows if it lost anything.

### 2. Tap the OUTBOUND path (server → client)

In `MAKE_SEND_BUFFER`, **before** `makeFull(m_key)` encrypts:

```cpp
// packet_func_sv.cpp — inside pkt_record(), before makeFull runs
auto buf = _p.getPlainBuf();   // .len = what was WRITTEN (getSizePlain is capacity = garbage!)
if (buf.buf == nullptr || buf.len == 0) return;

pkttap::record(pkttap::SRC_GAME, pkttap::DIR_OUT, uid, _s->m_oid,
               _p.getTipo(), buf.buf, (uint32_t)buf.len);
```

```cpp
#define MAKE_SEND_BUFFER(_packet, _session) pkt_record((_packet), (_session)); \
                         (_packet).makeFull((_session)->m_key); \
                         ...
```

### 3. Tap the INBOUND path (client → server)

In `MAKE_BEGIN_PACKET_SERVER`, **after** `unMake` has decrypted the packet:

```cpp
// packet_func_sv.h — the packet is plaintext here, and pd is fully built
#define _PKT_TAP_IN pkttap::record(pkttap::SRC_GAME, pkttap::DIR_IN, pd._session.m_pi.uid, \
                                   pd._session.m_oid, pd._packet->getTipo(), \
                                   pd._packet->getPlainBuf().buf, \
                                   (uint32_t)pd._packet->getPlainBuf().len);

#define _MAKE_BEGIN_PACKET_SERVER(_arg1, _arg2) \
        MAKE_BEGIN_SERVER(_arg1) _MAKE_BEGIN_PACKET(_arg2) _PKT_TAP_IN
```

### ⚠️ Two traps we hit (so you don't)

- **Don't tap the "return" dispatch table** (`funcs_sv`, the `packet_sv*` handlers). It re-dispatches each packet *after* the server already sent it — tapping there records the OUTBOUND packet a second time, masked as INBOUND (server→client opcode, blank name, wrong direction). It inflates counts and breaks the diff. Use a separate `MAKE_BEGIN_PACKET_SERVER_RET` **without** `_PKT_TAP_IN` for those six handlers. (Proven on the first real test: OUT `0x1B1` and IN `0x1B1` came byte-for-byte identical.)
- **`execCmd` is *not* a generic tap point** (the obvious single-point idea for all 5 servers). Its `void* _arg` changes type per server — `ParamDispatch*` in Game, a raw `packet*` in Auth. A generic tap there reads the pointer as the wrong type and crashes the server. Tap only where the arg is provably `ParamDispatch`.

### 4. Generate opcode names from ground truth

`tools/gen_opcodes.py` reads the **server source** to name every opcode — it deduces nothing:

- **IN**: the real dispatch table (`funcs.addPacketCall(0x02, packet_func::packet002, ...)`) + the semantic comment.
- **OUT**: the function that *builds* the packet (`init_plain((unsigned short)0x76)` + the enclosing function name). e.g. `0x76 = TourneyBase::sendInitialData | ...`.

Re-run it whenever the server changes. (Watch the same `funcs_sv` trap here: match only `\bfuncs\.addPacketCall`, or the return-table entries clobber the real handler names.)

---

## Install & run

1. **`GhostSniffer.exe`** — grab it from [Releases](../../releases). It's a standalone x64 binary (no .NET, no VC++ redist, no DLLs to install).
2. **`server/pkt_tap.h`** — drop it somewhere shared in your server tree and add the two taps (see *Server-side setup* above). This is the only file you touch on the server.
3. **Run order:** open `GhostSniffer.exe` **first** (it listens on `9931`), then start your Game Server. The tap connects on its own and reconnects if the app drops. The header turns green: `LIGADO (1 fonte)`.

That's it. Every PangYa server on the Acrisio base is the same code, so the opcode names baked into the app already match — no regeneration needed.

> **Optional — regenerate opcode names.** If your fork renamed handlers, run `python tools/gen_opcodes.py` against your source to rebuild `opcodes_gen.h`, then recompile the app (x64, MSBuild + v145; *not* CMake — CMake 4.1.1 has no generator for VS18). This is only needed if the default names drift.

> **Optional — Claude/MCP integration.** The `mcp/` folder (`sniffer_mcp.py` + `decoders.py`) lets Claude query the live capture. Point your `.mcp.json` at `sniffer_mcp.py` (stdio, zero dependencies — stdlib only). See `mcp/mcp.json.example`.

---

## Using it

### The app (visual)

- **Pacotes tab** — live packet list with the ground-truth name of each opcode, per-session tabs, hex + "readable text" view, filters (opcode / name / direction / hide sync+heartbeat).
- **Compare tab** — **broadcast audit.** For each burst (same opcode, same millisecond, 2+ recipients) it answers: *did someone not receive it?* and *did it arrive with different bytes for someone?* The plain `diff` compares counts, so it's blind to the packet that arrives for everyone but with **different bytes** — the silent desync. That was exactly the roster bug: the late-joiner's `0x76` *arrived*, just wrong.

### The MCP (Claude queries the live capture)

Registered in the project's `.mcp.json`; the app's port `9932` speaks a dumb line protocol and the Python MCP translates tool calls to it (zero C++ JSON parser — only an emitter). 11 tools:

| tool | what it does |
|------|--------------|
| `sniffer_status` | live: sources, packets, **drops** (>0 = capture not intact), bytes |
| `sniffer_sessions` | each UID seen, with count + time window |
| `sniffer_query` | list packets, filter by uid/opcode/dir/name/src, hex preview |
| `sniffer_packet` | one packet by seq, full hex + the server function that built it + struct **decode** |
| `sniffer_timeline` | the **structural skeleton**: create-room / start / late-join / init-hole / char-intro / shots / change-turn / ball position / finish, with the `0x33` crash message decoded. First tool to call when something breaks. |
| `sniffer_compare` | the broadcast audit (same as the Compare tab) |
| `sniffer_balls` | ball trail: decodes `0x64` (`ShotSyncData` = oid + x/y/z + state) |
| `sniffer_diff` | opcodes one session saw and the other didn't (by count) |
| `sniffer_wait` | block until a matching NEW packet arrives ("watch it happen live") |
| `sniffer_stats` | (dir,opcode) → count+bytes histogram — "what dominates the capture?" |
| `sniffer_export` | dump the capture with full hex to a JSON file for offline analysis |

**Struct decoding** lives in `mcp/decoders.py` (`DECODERS[(opcode,dir)]`), each decoder reading the payload the way the *server* reads it (ground truth). Adding one is editing that file — zero rebuild.

> **A packet is a binary struct, not text.** The "readable text" view is a heuristic (like unix `strings`) and *lies by construction*: a number whose bytes fall in the ASCII range shows up as letters (the uid `14643` / `0x3933` made the nick `lbarceloss` look like `lbarceloss39`). The struct decode is the source of truth.

---

## Field notes: the case this tool was built to crack

Ghost Sniffer wasn't built in the abstract — it was built to crack **versus reconnect / late-join** (dropping out of a 1v1 and coming back). What follows is the actual investigation log, in order. It doubles as a demonstration of the method: *ask the packets, not your assumptions.*

### The tool found and fixed two of its own bugs on the first real run

1. **Double-capture** — every server→client packet arrived twice, once correct as `DIR_OUT` and once bogus as `DIR_IN`, byte-for-byte identical. Root cause was the `funcs_sv` return-table sharing the IN tap macro (see trap #1 above). One surgical macro fixed it, and the tool *confirmed its own fix live*: "no server→client opcode appears as IN anymore."
2. **Blank opcode names** on shot packets — `gen_opcodes.py` read the return-table entry (nameless) *after* the real handler and overwrote it. Same root cause, different layer. Matching only `\bfuncs\.addPacketCall` fixed it and dropped the IN table from 402 phantom opcodes to 196 real ones.

### Late-join: the six-symptom chase that was really one race

The late-joiner needs ~10s to settle: load the course (`0x11`) → catch-up (`0xA3/0x9E/0x5B/0x53/0x115`) → **character intro (~8s)** → `0x34` = ready. But the match **doesn't wait**: the current shot's gate closes and `changeTurn` fires the `0x63` into the middle of his ceremony. He desyncs, waits 20s for a turn that already passed, hits the client's own timeout (`0x33` = `PM_NET_NEXT_TURN / ET(20031)`), dies — and takes the healthy clients down with him.

Five rounds of patching gate-by-gate only **moved** the symptom, because the root isn't the gate — **it's the race.**

- **The `0x33` opcode is the oracle.** The client confesses its own crash in plaintext before dying. `sniffer_query opcode=33` — always read it before theorizing.
- **The fix is to hold the turn**, not to pause. `pauseTime()` only freezes the shot clock (`m_timer`); the `checkVersusTurn` thread that emits `0x63` never looks at the pause state, so pausing alone leaves the race untouched. The real fix holds `changeTurn` while anyone is loading — **zero new packets**, it just delays the `0x63` by ~10s. That matters: *when the healthy client does X and yours does X+Y, suspect the Y before you blame the client.*
- The `sniffer_timeline` proved it: `0x34` ready → `0x63` **one millisecond later**, and the late-joiner then played the next shot as a normal player.

### The lesson that repeats

Three separate times this project blamed the client and the culprit was the server. The reconnect crash was **our own packet ordering** (we built the roster, then sent — in the very next packet — the command that dismantles it). The late-join kick was **our own timer** re-arming on a `0x1C` that arrived out of context. Every time, the answer came from an **address** matching between two tools, or from the client's own `0x33` confession — never from a guess.

---

## Why "impossible from the outside" is the whole point

The bytes exist in plaintext in our address space by construction. We don't attack the crypto — we stand where the plaintext already is. Everything downstream (the ground-truth names, the struct decoders, the live MCP queries, the broadcast audit) is only possible because step one isn't "break the encryption," it's "read our own memory."

---

*Ghost Sniffer — [hkfirewall.com](https://www.hkfirewall.com)*

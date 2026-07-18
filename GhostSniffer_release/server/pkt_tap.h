// Arquivo pkt_tap.h
// Criado em 17/07/2026
// Tap de pacotes EM TEXTO CLARO (o "sniffer" do dono do servidor).
//
// A IDEIA: nao existe nada pra quebrar. De fora, sniffar PangYa exige vencer Themida + GameGuard
// + a cripto, e ainda assim se adivinha o protocolo no fio (e o teto do sniffer do Adalink). Mas
// o texto claro nasce DENTRO deste processo: nos montamos o packet e SO DEPOIS aplicamos a chave.
// Entao o tap fica exatamente na fronteira:
//
//   SAIDA  (server->client): MAKE_SEND_BUFFER, ANTES do `makeFull(m_key)`   [packet_func_sv.cpp]
//   ENTRADA (client->server): MAKE_BEGIN_PACKET_SERVER, DEPOIS do `unMake`  [packet_func_sv.h]
//
// Resultado: 100% dos bytes, os dois sentidos, sem decripta, sem heuristica, validado pelo proprio
// jogo -- e com a VERDADE junto (uid/oid/opcode que o server ja conhece).
//
// ---------------------------------------------------------------------------------------------
// REGRA DE OURO DESTE ARQUIVO: **NUNCA ATRAPALHAR O JOGO.**
// Este tap roda DENTRO do caminho de envio/recebimento, em varias threads do IOCP. Entao:
//   1. ZERO I/O aqui. (O `pkt_record` antigo fazia fopen/fprintf/fclose POR PACOTE, dentro do send
//      path. Servia p/ debugar 1 UID; ligado pra todo mundo derruba o server -- e pior, MUDA O
//      TIMING, e a gente caca bug de corrida. Foi por isso que ele foi aposentado.)
//   2. So memcpy pra um ring em RAM sob um lock curtissimo; quem faz socket e a thread de dreno.
//   3. Se o app nao estiver aberto, custo = 1 leitura de flag e volta.
//   4. Ring cheio => DESCARTA e CONTA. O contador vai em todo frame: o app SEMPRE sabe se perdeu
//      pacote. Um sniffer que mente sobre o que perdeu nao serve pra debugar.
// ---------------------------------------------------------------------------------------------
//
// Header-only de proposito: os .vcxproj listam os .cpp um por um (335 entradas no Game Server),
// entao um .cpp novo exigiria mexer no build de cada server. Assim e so #include.

#pragma once
#ifndef _STDA_PKT_TAP_H
#define _STDA_PKT_TAP_H

#if defined(_WIN32)

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <stdint.h>

namespace pkttap {

	enum { TAP_PORT = 9931 };					// o APP escuta; os taps conectam (fan-in)
	enum { TAP_MAGIC = 0x50545950u };			// 'PYTP'
	enum { TAP_VERSION = 1 };

	enum { RING_SIZE = 32u * 1024u * 1024u };	// 32 MB. Potencia de 2 (o mask depende disso).
	enum { MAX_PKT = 512u * 1024u };			// sanidade: o 0x76 com 4 players da ~51 KB

	// Direcao, do ponto de vista do SERVER
	enum Dir { DIR_OUT = 0, DIR_IN = 1 };

	// Quem gerou o frame
	enum Src { SRC_AUTH = 1, SRC_LOGIN = 2, SRC_GAME = 3, SRC_MESSAGE = 4, SRC_GGAUTH = 5 };

#pragma pack(push, 1)
	struct Frame {
		uint32_t magic;		// TAP_MAGIC -- o app re-sincroniza por ele se algo sair da ordem
		uint16_t ver;
		uint16_t src;		// Src
		uint8_t  dir;		// Dir
		uint8_t  pad;
		uint64_t ts;		// FILETIME (100ns, UTC)
		uint32_t uid;
		uint32_t oid;
		uint16_t opcode;
		uint32_t len;		// bytes de payload logo apos este header
		uint32_t drops;		// pacotes perdidos ATE AQUI (ring cheio). 0 = nao perdi nada.
	};
#pragma pack(pop)

	class Tap {
		public:
			static Tap& getInstance() {
				static Tap s_inst;
				return s_inst;
			}

			// Chamado do caminho do jogo. Precisa ser barato e nunca bloquear.
			void record(uint16_t _src, uint8_t _dir, uint32_t _uid, uint32_t _oid, uint16_t _opcode,
					const void* _data, uint32_t _len) {

				// App fechado = caminho normal do server, custo ~zero.
				if (m_connected == 0)
					return;

				if (_data == nullptr || _len == 0 || _len > MAX_PKT)
					return;

				Frame f;

				f.magic  = TAP_MAGIC;
				f.ver    = TAP_VERSION;
				f.src    = _src;
				f.dir    = _dir;
				f.pad    = 0;
				f.ts     = nowFileTime();
				f.uid    = _uid;
				f.oid    = _oid;
				f.opcode = _opcode;
				f.len    = _len;
				f.drops  = (uint32_t)m_drops;

				const uint64_t total = (uint64_t)sizeof(Frame) + _len;

				EnterCriticalSection(&m_cs);

				if ((uint64_t)RING_SIZE - (m_head - m_tail) < total) {

					// Ring cheio: descarta ESTE pacote inteiro (nunca metade -- o app perderia o
					// sync). O proximo frame que passar avisa o app pelo campo `drops`.
					m_drops++;

					LeaveCriticalSection(&m_cs);
					return;
				}

				put(&f, sizeof(Frame));
				put(_data, _len);

				LeaveCriticalSection(&m_cs);
			}

		private:
			Tap() : m_head(0), m_tail(0), m_drops(0), m_connected(0), m_stop(0), m_sock(INVALID_SOCKET),
					m_ring(nullptr), m_thread(nullptr) {

				WSADATA wsa;

				// Refcontado: o server ja chamou. Chamar de novo e inofensivo e nos protege caso o
				// tap suba antes.
				WSAStartup(MAKEWORD(2, 2), &wsa);

				InitializeCriticalSection(&m_cs);

				m_ring = (uint8_t*)VirtualAlloc(nullptr, RING_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

				if (m_ring != nullptr)
					m_thread = CreateThread(nullptr, 0, &Tap::threadEntry, this, 0, nullptr);
			}

			~Tap() {

				InterlockedExchange(&m_stop, 1);

				if (m_thread != nullptr) {
					WaitForSingleObject(m_thread, 2000);
					CloseHandle(m_thread);
				}

				closeSock();

				if (m_ring != nullptr)
					VirtualFree(m_ring, 0, MEM_RELEASE);

				DeleteCriticalSection(&m_cs);
			}

			Tap(const Tap&);
			Tap& operator=(const Tap&);

			static uint64_t nowFileTime() {
				FILETIME ft;
				GetSystemTimeAsFileTime(&ft);	// nao e syscall: le do KUSER_SHARED_DATA
				return ((uint64_t)ft.dwHighDateTime << 32) | (uint64_t)ft.dwLowDateTime;
			}

			// Escreve no ring. Chamar SEMPRE com m_cs tomado e com espaco ja conferido.
			void put(const void* _src, size_t _n) {

				const size_t off = (size_t)(m_head & (uint64_t)(RING_SIZE - 1));
				const size_t ate_fim = (size_t)RING_SIZE - off;

				if (_n <= ate_fim)
					memcpy(m_ring + off, _src, _n);
				else {	// da a volta no ring
					memcpy(m_ring + off, _src, ate_fim);
					memcpy(m_ring, (const uint8_t*)_src + ate_fim, _n - ate_fim);
				}

				m_head += _n;
			}

			static DWORD WINAPI threadEntry(LPVOID _p) {
				((Tap*)_p)->threadLoop();
				return 0;
			}

			void threadLoop() {

				uint8_t buf[64 * 1024];

				while (InterlockedCompareExchange(&m_stop, 0, 0) == 0) {

					if (m_sock == INVALID_SOCKET) {

						if (!tryConnect()) {
							Sleep(1000);	// app fechado: tenta de novo daqui a pouco
							continue;
						}
					}

					// Tira um pedaco do ring (lock curto) e manda FORA do lock.
					size_t n = 0;

					EnterCriticalSection(&m_cs);

					const uint64_t disp = m_head - m_tail;

					if (disp > 0) {

						n = (size_t)((disp < sizeof(buf)) ? disp : sizeof(buf));

						const size_t off = (size_t)(m_tail & (uint64_t)(RING_SIZE - 1));
						const size_t ate_fim = (size_t)RING_SIZE - off;

						if (n <= ate_fim)
							memcpy(buf, m_ring + off, n);
						else {
							memcpy(buf, m_ring + off, ate_fim);
							memcpy(buf + ate_fim, m_ring, n - ate_fim);
						}

						m_tail += n;
					}

					LeaveCriticalSection(&m_cs);

					if (n == 0) {
						Sleep(2);	// nada pra mandar
						continue;
					}

					if (!sendAll(buf, n))
						closeSock();	// app fechou: volta a tentar conectar, jogo nem percebe
				}
			}

			bool tryConnect() {

				SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

				if (s == INVALID_SOCKET)
					return false;

				sockaddr_in sa;

				memset(&sa, 0, sizeof(sa));

				sa.sin_family = AF_INET;
				sa.sin_port = htons((u_short)TAP_PORT);
				sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

				if (connect(s, (sockaddr*)&sa, sizeof(sa)) != 0) {
					closesocket(s);
					return false;
				}

				BOOL nodelay = TRUE;
				setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

				m_sock = s;

				// So agora o record() comeca a gravar. Antes disso ele nem toca no ring.
				InterlockedExchange(&m_connected, 1);

				return true;
			}

			void closeSock() {

				InterlockedExchange(&m_connected, 0);

				if (m_sock != INVALID_SOCKET) {
					closesocket(m_sock);
					m_sock = INVALID_SOCKET;
				}

				// Descarta o que sobrou: sem app, o ring nao pode crescer.
				EnterCriticalSection(&m_cs);
				m_tail = m_head;
				LeaveCriticalSection(&m_cs);
			}

			bool sendAll(const uint8_t* _buf, size_t _n) {

				size_t enviado = 0;

				while (enviado < _n) {

					const int r = send(m_sock, (const char*)_buf + enviado, (int)(_n - enviado), 0);

					if (r <= 0)
						return false;

					enviado += (size_t)r;
				}

				return true;
			}

		private:
			CRITICAL_SECTION m_cs;

			uint8_t* m_ring;
			uint64_t m_head;	// monotonicos; o mask resolve a volta
			uint64_t m_tail;

			volatile LONG m_drops;
			volatile LONG m_connected;
			volatile LONG m_stop;

			SOCKET m_sock;
			HANDLE m_thread;
	};

	inline void record(uint16_t _src, uint8_t _dir, uint32_t _uid, uint32_t _oid, uint16_t _opcode,
			const void* _data, uint32_t _len) {

		Tap::getInstance().record(_src, _dir, _uid, _oid, _opcode, _data, _len);
	}
}

#endif	// _WIN32

#endif

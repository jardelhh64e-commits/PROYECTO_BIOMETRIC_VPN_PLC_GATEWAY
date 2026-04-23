import http.server, socketserver, urllib.parse, subprocess, os, argparse, sys
import datetime, hmac, hashlib, time, threading

REPLAY_WINDOW_SEC = 30   # tiempo de tolerancia 
nonce_cache = {}         
nonce_lock  = threading.Lock()

def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log(msg):
    print(f"[{now()}] {msg}", flush=True)

def sh(cmd, check=True):
    return subprocess.run(cmd, shell=True, check=check, text=True, capture_output=True).stdout.strip()

# limpieza de los nonces para proteccion de ataques
def _purge_nonces():
    cutoff = time.time() - REPLAY_WINDOW_SEC * 2
    with nonce_lock:
        expired = [n for n, t in nonce_cache.items() if t < cutoff]
        for n in expired:
            del nonce_cache[n]
    threading.Timer(REPLAY_WINDOW_SEC, _purge_nonces).start()

# verificacion del tiempo | el nonce antiguo | sobre la contraseña
def verify_request(secret: str, action: str, ts: str, nonce: str, sig: str) -> tuple[bool, str]:
    # 1.- tiempo espera
    try:
        req_time = float(ts)
    except ValueError:
        return False, "ts inválido"
    delta = abs(time.time() - req_time)
    if delta > REPLAY_WINDOW_SEC:
        return False, f"ts fuera de ventana ({delta:.1f}s)"

    # 2.- nonce antiguo
    with nonce_lock:
        if nonce in nonce_cache:
            return False, "nonce reutilizado "
        nonce_cache[nonce] = req_time

    # 3.- HMAC
    msg      = (action + ts + nonce).encode()
    expected = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, "firma inválida"

    return True, "ok"

# microsegmentacion de redes en el gatway
def detect_interfaces():
    ztif = sh("ip -br link | awk '/^zt/{print $1; exit}'")
    eth  = sh("ip -br addr | awk '$1 !~ /^zt/ && $3 ~ /^192\\.168\\.0\\./{print $1; exit}' || true")
    if not eth:
        eth = sh("ip -br link | awk '$1 ~ /^(eth|en)/{print $1; exit}'")
    if not ztif or not eth:
        raise RuntimeError("No pude detectar ZTIF/ETH")
    return ztif, eth

def do_on():
    ztif, eth = detect_interfaces()
    sh("sysctl -w net.ipv4.ip_forward=1")
    sh(f"iptables -t nat -C POSTROUTING -o {eth} -j MASQUERADE || iptables -t nat -A POSTROUTING -o {eth} -j MASQUERADE")
    sh(f"iptables -C FORWARD -i {ztif} -o {eth} -j ACCEPT || iptables -A FORWARD -i {ztif} -o {eth} -j ACCEPT")
    sh(f"iptables -C FORWARD -i {eth} -o {ztif} -m conntrack --ctstate RELATED,ESTABLISHED || iptables -A FORWARD -i {eth} -o {ztif} -m conntrack --ctstate RELATED,ESTABLISHED")
    return f"RECONOCIMIENTO BIOMETRICO ACEPTADO: PROCESO DE DATOS ACTIVADO (ZTIF={ztif}, ETH={eth})"

def do_off():
    ztif, eth = detect_interfaces()
    sh("sysctl -w net.ipv4.ip_forward=0", check=False)
    sh(f"iptables -t nat -D POSTROUTING -o {eth} -j MASQUERADE", check=False)
    sh(f"iptables -D FORWARD -i {ztif} -o {eth} -j ACCEPT", check=False)
    sh(f"iptables -D FORWARD -i {eth} -o {ztif} -m conntrack --ctstate RELATED,ESTABLISHED", check=False)
    return f"RECONOCIMIENTO BIOMETRICO ACEPTADO: PROCESO DE DATOS DESACTIVADO (ZTIF={ztif}, ETH={eth})"

def get_status():
    ipf = sh("sysctl -n net.ipv4.ip_forward || echo 0", check=False)
    nat = sh("iptables -t nat -S | grep MASQUERADE || true", check=False)
    fwd = sh("iptables -S FORWARD | egrep 'zt|RELATED' || true", check=False)
    return f"STATUS:\nip_forward={ipf}\nNAT:\n{nat or '-'}\nFORWARD:\n{fwd or '-'}\n"

def get_zt_ip():
    ip = sh("ip -4 -o addr show zt* 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1", check=False)
    return ip or "0.0.0.0"

# recopialcion de los datos por el servidor HTTP 
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs     = urllib.parse.parse_qs(parsed.query)
        client = self.client_address[0]

        action = qs.get("action", ["status"])[0]
        ts     = qs.get("ts",     [""])[0]
        nonce  = qs.get("nonce",  [""])[0]
        sig    = qs.get("sig",    [""])[0]

        if not ts or not nonce or not sig:
            log(f"DENY {client} — faltan parámetros HMAC (ts/nonce/sig)")
            self._respond(403, "Forbidden: se requieren ts, nonce y sig\n")
            return

        ok, reason = verify_request(self.server.secret, action, ts, nonce, sig)
        if not ok:
            log(f"DENY {client} — {reason}")
            self._respond(403, f"Forbidden: {reason}\n")
            return

        try:
            if action == "on":
                msg = do_on()
                log(f"ON  autorizado para {client} -> {msg}")
            elif action == "off":
                msg = do_off()
                log(f"OFF autorizado para {client} -> {msg}")
            else:
                msg = get_status()
                log(f"STATUS solicitado por {client}")
            self._respond(200, msg + "\n")
        except Exception as e:
            log(f"ERROR con {client}: {e}")
            self._respond(500, f"ERROR: {e}\n")

    def _respond(self, code, body):
        self.send_response(code)
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args, **kwargs):
        pass

class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

# inicio del servidor http
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Ejecuta como root: sudo python3 zt_gateway_control_HMAC.py --token TU_CLAVE", file=sys.stderr)
        sys.exit(1)

    ap = argparse.ArgumentParser()
    ap.add_argument("--token", required=True, help="clave pre-compartida K (nunca viaja en la URL)")
    ap.add_argument("--port",  type=int, default=8088)
    ap.add_argument("--bind",  default=None, help="IP para escuchar; por defecto: IP de ZeroTier")
    args = ap.parse_args()

    _purge_nonces()   

    bind_addr = args.bind or get_zt_ip()
    srv = ThreadingHTTPServer((bind_addr, args.port), Handler)
    srv.secret = args.token
    log(f"Gateway HMAC-SHA256 escuchando en http://{bind_addr}:{args.port}")
    log(f"Ventana anti-replay: ±{REPLAY_WINDOW_SEC}s")
    srv.serve_forever()

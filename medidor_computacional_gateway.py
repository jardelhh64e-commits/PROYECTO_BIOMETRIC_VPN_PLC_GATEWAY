#medidor computacional del gateway /GPU/RAM/TEMP

import sys, time, signal, glob

STEP = int(sys.argv[1]) if len(sys.argv) > 1 else 2
TARGETS = ("zt_gateway_control", "zerotier-one")

running = True
def stop(*_):
    global running
    running = False
signal.signal(signal.SIGINT,  stop)
signal.signal(signal.SIGTERM, stop)

def cpu_times():
    with open("/proc/stat") as f:
        p = f.readline().split()
    u, ni, s, i = map(int, p[1:5])
    return u + ni + s + i, i

def ram_total_mb():
    with open("/proc/meminfo") as f:
        for line in f:
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) // 1024

def gateway_rss_mb():
    total_kb = 0
    for status_path in glob.glob("/proc/[0-9]*/status"):
        try:
            with open(status_path) as f:
                data = f.read()
            cmd_path = status_path.replace("status", "cmdline")
            with open(cmd_path) as f:
                cmdline = f.read().replace("\x00", " ")
            if any(t in data.splitlines()[0] or t in cmdline for t in TARGETS):
                for l in data.splitlines():
                    if l.startswith("VmRSS:"):
                        total_kb += int(l.split()[1])
                        break
        except (FileNotFoundError, ProcessLookupError, PermissionError, IndexError):
            continue
    return total_kb // 1024

def temp_c():
    with open("/sys/class/thermal/thermal_zone0/temp") as f:
        return int(f.read()) / 1000.0

print(f"[bench] Midiendo cada {STEP}s (Gateway + ZeroTier). Ctrl+C para terminar.")
prev_tot, prev_idle = cpu_times()
cpu_acc = ram_acc = temp_acc = 0.0
n = 0
ram_total = ram_total_mb()
t0 = time.time()

while running:
    time.sleep(STEP)
    if not running:
        break
    tot, idle = cpu_times()
    dtot, didle = tot - prev_tot, idle - prev_idle
    cpu_acc += (dtot - didle) * 100.0 / dtot if dtot else 0.0
    prev_tot, prev_idle = tot, idle

    ram_acc  += gateway_rss_mb()
    temp_acc += temp_c()
    n += 1

if n == 0:
    print("Sin muestras (ventana demasiado corta).")
    sys.exit(0)

dur = int(time.time() - t0)
print("\n========= RESULTADO =========")
print(f"CPU promedio (sistema) : {cpu_acc / n:.1f} %")
print(f"RAM Gateway + ZeroTier : {ram_acc / n:.0f} MB de {ram_total} MB disponibles")
print(f"Temperatura oper.      : {temp_acc / n:.1f} °C")

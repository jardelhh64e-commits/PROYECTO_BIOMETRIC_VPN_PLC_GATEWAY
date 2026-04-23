# ZeroTier Gateway Control

Servidor HTTP con autenticación HMAC-SHA256 que controla el reenvío de tráfico (NAT/iptables) entre la red ZeroTier y la LAN local. Corre en una Raspberry Pi como servicio de sistema.

## Estructura del proyecto

```
zt_gateway/
├── zt_gateway_control.py   # Script principal del servidor
├── zt_gateway.service      # Servicio systemd (autoarranque)
├── .env.example            # Plantilla de configuración del token
├── docs/                   # Documentación e informes (PDFs locales, no se suben)
└── README.md
```

## Requisitos

- Python 3.10+
- ZeroTier instalado y conectado a una red
- Ejecutar como root (necesita `iptables` y `sysctl`)

```bash
sudo apt install zerotier-one
```

---

## Configuración del token (clave secreta)

**El token NUNCA debe subirse al repositorio.** Se guarda en un archivo local solo en la Raspberry Pi.

**Paso 1** — Genera una clave segura:
```bash
openssl rand -hex 32
```

**Paso 2** — Guárdala en la Raspberry Pi:
```bash
sudo mkdir -p /etc/zt_gateway
echo "ZT_TOKEN=pega_aqui_la_clave_generada" | sudo tee /etc/zt_gateway/token.env
sudo chmod 600 /etc/zt_gateway/token.env
```

> El archivo `.env.example` en el repo muestra el formato exacto que debe tener ese archivo.

---

## Autoarranque con systemd (Raspberry Pi)

Para que el servicio se inicie automáticamente cada vez que se enciende la Raspberry Pi:

```bash
# 1. Copiar el archivo de servicio
sudo cp zt_gateway.service /etc/systemd/system/

# 2. Habilitar el servicio
sudo systemctl daemon-reload
sudo systemctl enable zt_gateway.service

# 3. Iniciarlo ahora mismo (sin reiniciar)
sudo systemctl start zt_gateway.service
```

Verificar que está corriendo:
```bash
sudo systemctl status zt_gateway.service
```

Ver logs en tiempo real:
```bash
sudo journalctl -u zt_gateway.service -f
```

---

## Uso manual (sin systemd)

```bash
sudo python3 zt_gateway_control.py --token TU_CLAVE_SECRETA
```

| Argumento | Default | Descripción |
|-----------|---------|-------------|
| `--token` | (requerido) | Clave pre-compartida HMAC |
| `--port`  | `8088` | Puerto HTTP |
| `--bind`  | IP de ZeroTier | IP donde escucha el servidor |

---

## Cómo activar / desactivar / ver estado

Todos los requests necesitan firma HMAC. Los parámetros requeridos son `ts` (timestamp), `nonce` (valor único) y `sig` (firma).

### Desde Python (cliente de ejemplo)

```python
import hmac, hashlib, time, uuid, requests

TOKEN  = "tu_clave_secreta"
IP     = "IP_ZEROTIER_DE_LA_RASPI"   # ej: 10.147.17.x
PORT   = 8088

def signed_request(action):
    ts    = str(time.time())
    nonce = uuid.uuid4().hex
    msg   = (action + ts + nonce).encode()
    sig   = hmac.new(TOKEN.encode(), msg, hashlib.sha256).hexdigest()
    url   = f"http://{IP}:{PORT}/?action={action}&ts={ts}&nonce={nonce}&sig={sig}"
    return requests.get(url).text

print(signed_request("on"))      # Activa el gateway
print(signed_request("off"))     # Desactiva el gateway
print(signed_request("status"))  # Ver estado actual
```

### Desde curl (bash helper)

```bash
TOKEN="tu_clave_secreta"
IP="IP_ZEROTIER_DE_LA_RASPI"
PORT=8088
ACTION="status"   # cambiar por: on | off | status

TS=$(python3 -c "import time; print(time.time())")
NONCE=$(python3 -c "import uuid; print(uuid.uuid4().hex)")
SIG=$(python3 -c "
import hmac, hashlib
msg = ('$ACTION' + '$TS' + '$NONCE').encode()
print(hmac.new('$TOKEN'.encode(), msg, hashlib.sha256).hexdigest())
")

curl "http://$IP:$PORT/?action=$ACTION&ts=$TS&nonce=$NONCE&sig=$SIG"
```

---

## Seguridad

- La clave nunca viaja en la URL; solo se usa para generar y verificar la firma HMAC-SHA256.
- Cada request incluye timestamp (`ts`) y nonce único para prevenir ataques de replay.
- La ventana de tolerancia de tiempo es ±30 segundos.
- El archivo de token tiene permisos `600` (solo root puede leerlo).

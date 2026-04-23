# PROYECTO_BIOMETRIC_VPN_PLC_GATEWAY

Lado Raspberry Pi del sistema de control remoto biometrico de un PLC Siemens S7. Este repositorio contiene el gateway que corre en la Pi, recibe comandos firmados desde la laptop por la VPN ZeroTier, valida la firma HMAC-SHA256 y abre/cierra dinamicamente el tunel hacia el PLC mediante iptables. Corresponde al lado servidor del sistema descrito en el paper LACCEI 2026.

## Arquitectura

```
Laptop (cliente biometrico)
      |
      | HTTP firmado HMAC-SHA256 sobre ZeroTier
      v
Raspberry Pi  ->  zt_gateway_control.py  (servidor HTTP, valida ts+nonce+sig)
                       |
                       v
                  iptables / sysctl  (abre o cierra NAT y FORWARD)
                       |
                       v
                  PLC Siemens S7-1200/1500  (red LAN local)
```

## Requisitos

- Raspberry Pi con Raspberry Pi OS (o Linux equivalente)
- Python 3.10 o superior
- ZeroTier instalado y unido a la misma red que la laptop
- Acceso root (necesario para `iptables` y `sysctl`)
- PLC Siemens S7 alcanzable desde la red LAN de la Pi

```bash
sudo apt install zerotier-one
sudo zerotier-cli join <NETWORK_ID>
```

## Instalacion

```bash
# 1. Clonar el repo en la Raspberry Pi
git clone https://github.com/jardelhh64e-commits/PROYECTO_BIOMETRIC_VPN_PLC_GATWAY.git
cd PROYECTO_BIOMETRIC_VPN_PLC_GATWAY
```

## Configuracion (paso obligatorio)

Las credenciales NO viven en el codigo. Se leen desde un archivo `.env` local que NUNCA se sube al repositorio.

```bash
# Copiar la plantilla
cp .env.example .env
```

Editar `.env` y reemplazar los valores con los tuyos:

| Variable  | Descripcion |
|-----------|-------------|
| `ZT_TOKEN` | Clave pre-compartida entre laptop y gateway. Debe ser identica a `HMAC_KEY` del repo de la laptop. Generala con `openssl rand -hex 32`. |
| `ZT_HOST`  | IP ZeroTier de esta Raspberry Pi (ej. `10.x.x.x`). |
| `ZT_PORT`  | Puerto HTTP del gateway. Default: `8088`. |

El archivo se lee desde `/etc/zt-gateway.env` cuando corre como servicio systemd. Para mover los valores ahi:

```bash
sudo cp .env /etc/zt-gateway.env
sudo chmod 600 /etc/zt-gateway.env
```

## Ejecutar

### Modo manual (pruebas)

```bash
sudo python3 zt_gateway_control.py --token TU_CLAVE --port 8088
```

| Argumento | Default | Descripcion |
|-----------|---------|-------------|
| `--token` | (requerido) | Clave pre-compartida HMAC |
| `--port`  | `8088` | Puerto HTTP |
| `--bind`  | IP de ZeroTier | IP donde escucha el servidor |

### Modo servicio (auto-arranque en cada reboot)

```bash
sudo cp zt_gateway.service /etc/systemd/system/zt-gateway.service
sudo systemctl daemon-reload
sudo systemctl enable --now zt-gateway.service
```

Verificar estado y ver logs en vivo:

```bash
sudo systemctl status zt-gateway
sudo journalctl -u zt-gateway -f
```

## Comandos aceptados

El gateway responde a tres acciones, todas firmadas con HMAC-SHA256 (`ts` + `nonce` + `sig`):

| Accion   | Efecto |
|----------|--------|
| `on`     | Abre NAT + FORWARD entre ZeroTier y la LAN del PLC |
| `off`    | Cierra NAT + FORWARD (PLC inalcanzable) |
| `status` | Devuelve estado de `ip_forward` y reglas iptables actuales |

## Modulos principales

| Archivo | Rol |
|---------|-----|
| `zt_gateway_control.py` | Servidor HTTP, validacion HMAC, control de iptables/sysctl |
| `zt_gateway.service`    | Unit de systemd para auto-arranque |
| `.env.example`          | Plantilla de configuracion (token, host, puerto) |

## Seguridad

- El codigo NO contiene claves hardcoded. Todas viven en `.env` (ignorado por git).
- La clave nunca viaja en la URL: solo se usa para generar y verificar la firma HMAC-SHA256.
- Cada request incluye `ts` (timestamp) y `nonce` unico para prevenir ataques de replay.
- Ventana de tolerancia temporal: ±30 segundos.
- El archivo de credenciales tiene permisos `600` (solo root).
- Ver paper LACCEI 2026 para el analisis completo del esquema.

## Cliente (laptop)

El codigo del cliente biometrico (reconocimiento facial, anti-spoofing y firma HMAC) vive en un repositorio aparte:

`https://github.com/jardelhh64e-commits/PROYECTO_BIOMETRIC_VPN_PLC_LAPTOP`

## Licencia

Uso academico.

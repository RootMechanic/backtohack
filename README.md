# BacktoHack — Buscador asíncrono de backups expuestos

> Script en **Python** para buscar copias de seguridad (ZIP/RAR/7z/GZ) mediante candidatos comunes. Escanea dominios en paralelo usando **httpx** y valida por cabeceras **y** firmas mágicas (magic bytes).

```
 ____    _    ____ _  _______ ___  _   _    _    ____ _  __
| __ )  / \  / ___| |/ /_   _/ _ \| | | |  / \  / ___| |/ /
|  _ \ / _ \| |   | ' /  | || | | | |_| | / _ \| |   | ' / 
| |_) / ___ \ |___| . \  | || |_| |  _  |/ ___ \ |___| . \ 
|____/_/   \_\____|_|\_\ |_| \___/|_| |_/_/   \_\____|_|\_```
**Desarrollado por RootMechanic**
```
---

## ✨ Características

- ⚡ **Asíncrono y concurrente** (HTTP/2 con `httpx`) para máximo rendimiento.
- 🧠 **Candidatos inteligentes**: combina `dominio.zip`, `sld.zip`, y `wordpress.zip`, `joomla.zip`, etc.
- 🧪 **Detección real de archivos**: inspección de cabeceras (`Content-Type`, `Content-Disposition`) y **magic bytes** con lectura parcial (`Range: bytes=0-511`).
- 🛡️ **Reducción de falsos positivos** y deduplicación por hash parcial y destino final.
- 👨‍💻 **Asistente interactivo** con valores por defecto claros.
- 🖨️ **Resumen final** de hallazgos únicos y métricas.

---

## 📦 Requisitos

- Python **3.8+**
- `httpx >= 0.27.0`

---

## 🚀 Uso rápido

### 1) Con fichero de dominios (uno por línea)

```bash
python3 backtohack.py dominios.txt
```

### 2) Modo asistente (sin argumentos)

```bash
python3 backtohack.py
```

En el asistente, **pulsa Intro** para aceptar los valores por defecto mostrados entre corchetes.

---

## ⚙️ Parámetros de línea de comandos

| Opción | Descripción | Por defecto |
|---|---|---|
| `file` | Fichero con dominios (uno por línea). Si se omite, se lanza el asistente. | — |
| `--exts` | Extensiones de archivo a probar (CSV). | `zip,rar` |
| `--cms` | Nombres de CMS para generar candidatos (CSV). | `wordpress,joomla` |
| `--max-candidates` | Máximo de combinaciones por dominio. | `10` |
| `-j`, `--concurrency` | Concurrencia global de peticiones. | `20` |
| `--connect-timeout` | Timeout de conexión (s). | `6` |
| `--max-time` | Timeout total por petición (s). | `15` |
| `--no-banner` | Oculta el título ASCII. | — |

Ejemplos:

```bash
# Más cobertura (más candidatos) y más concurrencia
python3 backtohack.py dominios.txt --max-candidates 25 -j 50

# Escaneo discreto (menos candidatos, timeouts cortos)
python3 backtohack.py dominios.txt --max-candidates 5 --connect-timeout 3 --max-time 6
```

---

## 🧩 Cómo genera candidatos

Para cada dominio se calculan combinaciones como:

- `base`: segundo nivel + TLD (p. ej. `ejemplo.com`) → `ejemplo.com.zip`
- `sld`: solo el segundo nivel (p. ej. `ejemplo`) → `ejemplo.zip`
- `cms`: nombres de CMS provistos → `wordpress.zip`, `joomla.rar`, etc.

Se limita el total por dominio con `--max-candidates` para equilibrar **cobertura** y **ruido**.

---

## 🔍 Cómo detecta archivos reales

1. **Cabeceras**: `Content-Type` y `Content-Disposition` compatibles con ZIP/RAR/7z/GZ/TAR.
2. **Magic bytes**: validación de firmas conocidas (`PK\x03\x04`, `Rar!\x1A\x07...`, `7z`…), leyendo solo los **primeros 512 bytes** con `Range`.

Solo se marca como **HIT** si las cabeceras o las firmas mágicas son consistentes.

---

## 🧾 Formato de salida

Mensajes por URL candidata:

- `"[UP]"` / `"[DOWN]"` → estado del host y esquema (`http`/`https`).
- `"[HIT]"` → copia detectada (única).
- `"[DUP]"` → duplicado del mismo recurso final.
- `"[MISS]"` → no coincide.
- `"[FP]"` → falso positivo (cabecera sospechosa sin firmas, etc.).

Ejemplo:

```
[UP]    sub.example.es (https)
[HIT]   https://sub.example.es/wordpress.zip (size: 1048576 bytes)
[DUP]   https://sub.example.es/ejemplo.zip -> https://example.../wordpress.zip
[FP]    https://sub.example.es/backup.zip  (Content-Type: text/html)
[MISS]  https://sub.example.es/joomla.rar
```

Al final, se imprime un **resumen** con métricas y la lista de **copias únicas** encontradas (URL → destino final, tamaño, `Content-Type`).

---

## 🧪 Buenas prácticas y reducción de ruido

- Ajusta `--max-candidates` a tu caso. **Más** combinaciones ⇒ **más** tráfico.
- Usa `-j/--concurrency` con cabeza: conexiones excesivas pueden activar defensas.
- Timeouts (`--connect-timeout`, `--max-time`) **demasiado** bajos causan `DOWN`/`MISS` falsos.
- Revisa manualmente los `"[FP]"` cuando el sitio devuelve HTML genérico con `200`.

---

## 🕵️‍♂️ Consideraciones legales y éticas

Este software es para **auditorías autorizadas** y **concienciación**. **No** lo utilices sin permiso explícito del titular de los sistemas. Tú eres el responsable del uso que hagas de la herramienta.

---

## 📁 Ejemplo de `dominios.txt`

```
example.com
subdominio.ejemplo.org
www.empresa.es
```

Líneas vacías o que empiezan por `#` se ignoran.

---

## 🧰 Configuración y personalización

- **User-Agent:** por defecto es `RootMechanic-BacktoHack/1.0`. Puedes **editar** la constante `USER_AGENT` en el código. (En el *roadmap* se contempla permitir `--user-agent` o rotación aleatoria.)
- **Extensiones y CMS**: añade los tuyos en `--exts` y `--cms` (CSV).
- **Sin banner**: `--no-banner` si quieres salida más limpia.

---

## 🐛 Solución de problemas

- *Demasiados `[DOWN]`*: comprueba DNS/IPv6, corta `--concurrency`, sube timeouts.
- *Demasiados `[FP]`*: añade más extensiones reales, o valida manualmente si el sitio responde con HTML para todo.
- *Bloqueos/WAF*: baja `-j`, introduce esperas externas, o limita `--max-candidates`.
- *Python SSL* en entornos viejos: actualiza `certifi` o el *trust store* del sistema.

---

## 🗺️ Roadmap (ideas)

- Salida a **CSV/JSON** de hallazgos.
- Opción `--user-agent` y **rotación**.
- Soporte para **listas de rutas** personalizadas por dominio.
- **Reintentos** configurables y *backoff*.
- **Proxy**/TOR y control de **rate limit**.

---

## 🤝 Contribuir

¡Las PRs son bienvenidas! Abre un *issue* con propuestas, *bugs* reproducibles o ideas de mejora.


## 👤 Autoría

- **RootMechanic** — mantenimiento y diseño actual de BacktoHack.

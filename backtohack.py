#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
backtohack.py  —  Versión asíncrona en Python del buscador de backups.
Uso rápido:
  python3 backtohack.py dominios.txt
  (sin argumentos) -> asistente interactivo

Requisitos:
  pip install httpx>=0.27.0
"""

import asyncio
import httpx
import argparse
import sys
import os
import re
import hashlib
from typing import List, Tuple, Dict, Optional

# ----------------------- Config por defecto -----------------------
DEFAULT_EXTS = "zip,rar"
DEFAULT_CMS = "wordpress,joomla"
DEFAULT_FILE = "./dominios.txt"
MAX_CANDIDATES_DEFAULT = 10
CONNECT_TIMEOUT_DEFAULT = 6
MAX_TIME_DEFAULT = 15
CONCURRENCY_DEFAULT = 20
USER_AGENT = "RootMechanic-BacktoHack/1.0"

# -------------------------- Colores -------------------------------
def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM") not in (None, "dumb")

if _supports_color():
    RED, GREEN, YELLOW, BLUE, CYAN, MAGENTA = "\033[31m", "\033[32m", "\033[33m", "\033[34m", "\033[36m", "\033[35m"
    BOLD, RESET = "\033[1m", "\033[0m"
else:
    RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = BOLD = RESET = ""

def msg_up(host: str, scheme: str):     print(f"{GREEN}[UP]{RESET}    {host} ({scheme})")
def msg_down(host: str):                print(f"{YELLOW}[DOWN]{RESET}  {host}")
def msg_hit(url: str, extra: str = ""): print(f"{RED}[HIT]{RESET}   {url}  {extra}")
def msg_dup(url: str, final: str):      print(f"{BLUE}[DUP]{RESET}   {url} -> {final}")
def msg_miss(url: str):                 print(f"{CYAN}[MISS]{RESET}  {url}")
def msg_fp(url: str, why: str = ""):    print(f"{YELLOW}[FP]{RESET}    {url}  {why}")
def msg_info(txt: str):                 print(f"{BOLD}{txt}{RESET}")

# ----------------------- Banner / Título --------------------------
def print_banner(show: bool = True):
    if not show: 
        return
    art = r"""
 ____    _    ____ _  _______ ___  _   _    _    ____ _  __
| __ )  / \  / ___| |/ /_   _/ _ \| | | |  / \  / ___| |/ /
|  _ \ / _ \| |   | ' /  | || | | | |_| | / _ \| |   | ' / 
| |_) / ___ \ |___| . \  | || |_| |  _  |/ ___ \ |___| . \ 
|____/_/   \_\____|_|\_\ |_| \___/|_| |_/_/   \_\____|_|\_\
"""
    print(art)
    print(f"{MAGENTA}{BOLD}Desarrollado por RootMechanic{RESET}\n")

# -------------------------- Utilidades ----------------------------
def base_and_sld(domain: str) -> Tuple[str, str]:
    parts = domain.strip().split(".")
    if len(parts) >= 2:
        base = ".".join(parts[-2:])
        sld = parts[-2]
    else:
        base = domain
        sld = domain
    return base, sld

def build_candidates(domain: str, exts_csv: str, cms_csv: str, max_candidates: int) -> List[str]:
    base, sld = base_and_sld(domain)
    exts = [e.strip() for e in exts_csv.split(",") if e.strip()]
    cmss = [c.strip() for c in cms_csv.split(",") if c.strip()]
    seen = set()
    out: List[str] = []
    for e in exts:
        for name in (f"{base}.{e}", f"{sld}.{e}"):
            if name not in seen:
                out.append(name); seen.add(name)
    for c in cmss:
        for e in exts:
            name = f"{c}.{e}"
            if name not in seen:
                out.append(name); seen.add(name)
    return out[:max_candidates]

MAGIC_PATTERNS = [
    (b"\x50\x4B\x03\x04", "zip"),
    (b"\x50\x4B\x05\x06", "zip"),
    (b"\x50\x4B\x07\x08", "zip"),
    (b"\x52\x61\x72\x21\x1A\x07\x00", "rar"),
    (b"\x52\x61\x72\x21\x1A\x07\x01\x00", "rar"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "7z"),
    (b"\x1F\x8B", "gz"),
]

def has_magic(buf: bytes) -> bool:
    return any(buf.startswith(sig) for sig, _ in MAGIC_PATTERNS)

_archive_ct_re = re.compile(
    r"application/(zip|x-zip-compressed|x-rar|x-rar-compressed|x-7z-compressed|octet-stream)",
    re.I,
)
def is_archive_by_headers(ctype: str, cdisp: str) -> bool:
    ctype = (ctype or "").strip()
    cdisp = (cdisp or "").strip()
    if _archive_ct_re.search(ctype):
        return True
    if "attachment" in cdisp.lower() and re.search(r"\.(zip|rar|7z|gz|tar(\.gz)?)\"?$", cdisp, re.I):
        return True
    return False

def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest() if data else "none"

# -------------------------- HTTP cliente --------------------------
def make_client(timeout_connect: int, timeout_total: int) -> httpx.AsyncClient:
    timeout = httpx.Timeout(timeout_total, connect=timeout_connect)
    limits = httpx.Limits(max_keepalive_connections=100, max_connections=200)
    headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    # follow_redirects=True para obtener cabeceras finales sin manejar hop-by-hop
    return httpx.AsyncClient(http2=True, timeout=timeout, limits=limits, headers=headers, follow_redirects=True)

async def is_up(client: httpx.AsyncClient, scheme: str, host: str) -> bool:
    url = f"{scheme}://{host}/"
    try:
        r = await client.get(url, headers={"Range": "bytes=0-0"})
        return 200 <= r.status_code < 400
    except httpx.HTTPError:
        return False

async def resolve_scheme(client: httpx.AsyncClient, host: str) -> Optional[str]:
    if await is_up(client, "https", host):
        return "https"
    if await is_up(client, "http", host):
        return "http"
    return None

async def probe_url(client: httpx.AsyncClient, url: str) -> Tuple[str, int, str, str, str, bytes]:
    """
    Devuelve: (final_url, status_code, content_type, content_length, content_disp, body512)
    """
    try:
        r = await client.get(url, headers={"Range": "bytes=0-511"})
        final_url = str(r.url)
        code = r.status_code
        ctype = r.headers.get("Content-Type", "")
        clen = r.headers.get("Content-Length", "")
        cdisp = r.headers.get("Content-Disposition", "")
        body = r.content or b""
        return final_url, code, ctype, clen, cdisp, body
    except httpx.HTTPError:
        # Simetría con Bash: devolver “código 0”
        return url, 0, "", "", "", b""

# -------------------------- Estado global -------------------------
class Stats:
    def __init__(self):
        self.total_domains = 0
        self.total_up = 0
        self.total_down = 0
        self.total_hits = 0
        self.total_dups = 0
        self.total_fp = 0

SEEN_SIG: set = set()  # domain|||final|clen|md5
HITS_MAP: Dict[str, Tuple[str, str, str, str]] = {}  # url -> (domain, final, clen, ctype)
HITS_LIST: List[str] = []

# -------------------------- Escaneo dominio -----------------------
async def scan_domain(
    client: httpx.AsyncClient,
    domain: str,
    exts: str,
    cmss: str,
    max_candidates: int,
    semaphore: asyncio.Semaphore,
    stats: Stats,
):
    stats.total_domains += 1
    scheme = await resolve_scheme(client, domain)
    if not scheme:
        msg_down(domain); stats.total_down += 1; return
    msg_up(domain, scheme); stats.total_up += 1

    candidates = build_candidates(domain, exts, cmss, max_candidates)

    async def _one(fname: str):
        url = f"{scheme}://{domain}/{fname}"
        async with semaphore:
            final, code, ctype, clen, cdisp, body = await probe_url(client, url)
        if code not in (200, 206):
            msg_miss(url); return

        is_arch = is_archive_by_headers(ctype, cdisp) or has_magic(body)
        if not is_arch:
            msg_fp(url, f"(Content-Type: {ctype or 'desconocido'})"); stats.total_fp += 1; return

        sig = f"{domain}|||{final}|{clen or 'none'}|{md5_hex(body)}"
        if sig in SEEN_SIG:
            msg_dup(url, final); stats.total_dups += 1; return

        SEEN_SIG.add(sig)
        size_str = f"(size: {clen} bytes)" if clen else ""
        msg_hit(url, size_str)
        HITS_MAP[url] = (domain, final, clen or "", ctype or "")
        HITS_LIST.append(url)
        stats.total_hits += 1

    await asyncio.gather(*[_one(fname) for fname in candidates])

# ----------------------- Asistente interactivo --------------------
async def interactive_wizard(args):
    print_banner(not args.no_banner)
    msg_info("=== Asistente interactivo ===")
    print(f"Pulsa {BOLD}Intro{RESET} para usar valores por defecto cuando se muestren entre corchetes.")

    one_domain = input("Introduce un dominio único (o deja vacío para usar fichero): ").strip()

    file_path = ""
    if not one_domain:
        while True:
            file_path = input(f"Ruta del fichero con dominios [{DEFAULT_FILE}] (Intro = por defecto): ").strip() or DEFAULT_FILE
            if file_path.lower() == "q":
                print("Cancelado."); sys.exit(1)
            if os.path.isfile(file_path):
                break
            else:
                print(f"{YELLOW}No existe:{RESET} {file_path}. Escribe otra ruta o 'q' para salir.")

    exts = input(f"Extensiones a probar [{DEFAULT_EXTS}] (Intro = por defecto): ").strip() or DEFAULT_EXTS
    cmss = input(f"CMS a probar [{DEFAULT_CMS}] (Intro = por defecto): ").strip() or DEFAULT_CMS

    print("\nEl parámetro 'Máximo de combinaciones por dominio' limita cuántos nombres se generan (dominio.zip, sld.zip, wordpress.zip,...).")
    print("— Subirlo => más cobertura; — Bajarlo => más rápido/discreto.")
    maxc_txt = input(f"Máximo de combinaciones por dominio [{MAX_CANDIDATES_DEFAULT}] (Intro = por defecto): ").strip()
    maxc = MAX_CANDIDATES_DEFAULT if not maxc_txt.isdigit() else max(1, int(maxc_txt))

    conc_txt = input(f"Concurrencia (-j) [{CONCURRENCY_DEFAULT}] (Intro = por defecto): ").strip()
    concurrency = CONCURRENCY_DEFAULT if not conc_txt.isdigit() else max(1, int(conc_txt))

    print("\n== Resumen de opciones ==")
    if one_domain:
        print(f"Dominio:              {one_domain}")
    else:
        print(f"Fichero de dominios:  {file_path}")
    print(f"Extensiones:          {exts}")
    print(f"CMS:                  {cmss}")
    print(f"Máx. combinaciones:   {maxc}")
    print(f"Concurrencia:         {concurrency}\n")

    client = make_client(args.connect_timeout, args.max_time)
    sem = asyncio.Semaphore(concurrency)
    stats = Stats()

    try:
        if one_domain:
            await scan_domain(client, one_domain, exts, cmss, maxc, sem, stats)
        else:
            async with client:
                for line in open(file_path, "r", encoding="utf-8", errors="ignore"):
                    domain = line.strip()
                    if not domain or domain.startswith("#"):
                        continue
                    await scan_domain(client, domain, exts, cmss, maxc, sem, stats)
    finally:
        await client.aclose()

    print_summary(stats)

# ----------------------------- CLI --------------------------------
def parse_args():
    p = argparse.ArgumentParser(
        description="Buscador de backups (ZIP/RAR/7z/GZ) por candidatos comunes — versión asíncrona.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("file", nargs="?", help="Fichero con dominios (uno por línea). Si se omite, asistente interactivo.")
    p.add_argument("--exts", default=DEFAULT_EXTS, help="Extensiones a probar (csv).")
    p.add_argument("--cms", default=DEFAULT_CMS, help="Nombres de CMS para generar candidatos (csv).")
    p.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES_DEFAULT, help="Máximo de combinaciones por dominio.")
    p.add_argument("-j", "--concurrency", type=int, default=CONCURRENCY_DEFAULT, help="Concurrencia global de peticiones.")
    p.add_argument("--connect-timeout", type=int, default=CONNECT_TIMEOUT_DEFAULT, help="Timeout de conexión (s).")
    p.add_argument("--max-time", type=int, default=MAX_TIME_DEFAULT, help="Timeout total por petición (s).")
    p.add_argument("--no-banner", action="store_true", help="Desactiva el título ASCII.")
    return p.parse_args()

def print_summary(stats: Stats):
    print()
    msg_info("==== RESUMEN ====")
    print(f"Dominios totales:   {stats.total_domains}")
    print(f"Dominios UP:        {stats.total_up}")
    print(f"Dominios DOWN:      {stats.total_down}")
    print(f"Copias únicas:      {stats.total_hits}")
    print(f"Duplicados:         {stats.total_dups}")
    print(f"Falsos positivos:   {stats.total_fp}")
    print()
    if HITS_LIST:
        msg_info("Copias encontradas (únicas):")
        for u in HITS_LIST:
            dom, fin, clen, ctype = HITS_MAP[u]
            size_part = f"(size: {clen} bytes) " if clen else ""
            print(f"  - {u} -> {fin}  {size_part}(CT: {ctype or 'desconocido'})")
    else:
        print("No se han encontrado copias con los criterios usados.")

# ----------------------------- Main -------------------------------
async def main_async():
    args = parse_args()
    if args.file is None:
        await interactive_wizard(args)
        return

    if not os.path.isfile(args.file):
        print(f"Archivo no encontrado: {args.file}", file=sys.stderr)
        sys.exit(1)

    print_banner(not args.no_banner)
    client = make_client(args.connect_timeout, args.max_time)
    sem = asyncio.Semaphore(max(1, args.concurrency))
    stats = Stats()

    try:
        async with client:
            with open(args.file, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    domain = line.strip()
                    if not domain or domain.startswith("#"):
                        continue
                    await scan_domain(client, domain, args.exts, args.cms, max(1, args.max_candidates), sem, stats)
    finally:
        await client.aclose()

    print_summary(stats)

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nInterrumpido por el usuario.", file=sys.stderr)

if __name__ == "__main__":
    main()

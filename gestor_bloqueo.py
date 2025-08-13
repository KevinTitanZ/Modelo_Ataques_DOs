#!/usr/bin/env python3
import os
import sys
import time
import ipaddress
import subprocess
from pathlib import Path
from typing import Set, Tuple, List

ARCHIVO_IPS = "posibles_ataques.txt"
ARCHIVO_WHITELIST = "lista_blanca.txt"
LOGFILE = "gestor_bloqueo.log"

IPSET_NAME_V4 = "dos_block_v4"
IPSET_NAME_V6 = "dos_block_v6"
IPTABLES_CHAIN = "DOS_GUARD"
IPTABLES6_CHAIN = "DOS_GUARD6"

# ---------- Utilidades de sistema ----------
def run(cmd: List[str], check=True, capture=False) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)

def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOGFILE, "a") as f:
        f.write(f"[{ts}] {msg}\n")
    print(msg)

def is_root() -> bool:
    return os.geteuid() == 0

def program_exists(name: str) -> bool:
    from shutil import which
    return which(name) is not None

def get_gateway_ip() -> str:
    # Linux: parse "ip route"
    try:
        out = run(["ip", "route"], check=True, capture=True).stdout
        for line in out.splitlines():
            if line.startswith("default via "):
                return line.split()[2]
    except Exception:
        pass
    return ""

def get_local_ips() -> Set[str]:
    ips = set()
    # "hostname -I" devuelve IPs locales
    try:
        out = run(["sh", "-c", "hostname -I"], capture=True).stdout.strip()
        for tok in out.split():
            ips.add(tok.strip())
    except Exception:
        pass
    return {ip for ip in ips if ip}

# ---------- Carga/guardado ----------
def cargar_ips(filename: str) -> Set[str]:
    try:
        with open(filename, "r") as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

def append_ip(filename: str, ip: str):
    # No reescribir todo si ya existe
    existing = cargar_ips(filename)
    if ip not in existing:
        with open(filename, "a") as f:
            f.write(ip + "\n")

# ---------- Validación ----------
def split_valid_ips(ips: Set[str]) -> Tuple[Set[str], Set[str]]:
    v4, v6 = set(), set()
    for ip in ips:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                v4.add(ip)
            else:
                v6.add(ip)
        except ValueError:
            log(f"[WARN] IP inválida ignorada: {ip}")
    return v4, v6

# ---------- ipset / iptables ----------
def ensure_ipset(ipv: int):
    name = IPSET_NAME_V4 if ipv == 4 else IPSET_NAME_V6
    set_type = "hash:ip"
    family = "inet" if ipv == 4 else "inet6"
    if not program_exists("ipset"):
        return False
    # crear si no existe
    try:
        run(["ipset", "list", name], check=True)
    except subprocess.CalledProcessError:
        run(["ipset", "create", name, set_type, "family", family, "timeout", "0"])
        log(f"[OK] Creado ipset {name}")
    return True

def ipset_add(ip: str):
    family = ipaddress.ip_address(ip).version
    name = IPSET_NAME_V4 if family == 4 else IPSET_NAME_V6
    try:
        run(["ipset", "add", name, ip], check=False)  # idempotente: no falla si ya está
        log(f"[OK] Añadida a ipset {name}: {ip}")
    except Exception as e:
        log(f"[ERR] ipset add {ip}: {e}")

def ensure_iptables_chain(ipv: int):
    chain = IPTABLES_CHAIN if ipv == 4 else IPTABLES6_CHAIN
    tool = "iptables" if ipv == 4 else "ip6tables"
    # crear cadena
    try:
        run([tool, "-nL", chain], check=True)
    except subprocess.CalledProcessError:
        run([tool, "-N", chain])
        log(f"[OK] Creada cadena {chain} en {tool}")

    # insertar salto desde INPUT al principio si no existe
    try:
        out = run([tool, "-S", "INPUT"], capture=True).stdout
        if f"-j {chain}" not in out:
            run([tool, "-I", "INPUT", "1", "-j", chain])
            log(f"[OK] Insertado salto INPUT -> {chain} en {tool}")
    except Exception as e:
        log(f"[ERR] No pude asegurar salto INPUT->{chain}: {e}")

    # añadir regla que dropea por ipset si no existe
    if program_exists("ipset"):
        name = IPSET_NAME_V4 if ipv == 4 else IPSET_NAME_V6
        try:
            out = run([tool, "-S", chain], capture=True).stdout
            marker = f"-m set --match-set {name} src -j DROP"
            if marker not in out:
                run([tool, "-A", chain, "-m", "set", "--match-set", name, "src", "-j", "DROP"])
                log(f"[OK] Regla {chain}: DROP si src in {name}")
        except Exception as e:
            log(f"[ERR] No pude añadir regla de ipset en {tool}: {e}")

def block_with_iptables(ip: str):
    # Fallback (sin ipset): regla específica idempotente con comentario
    family = ipaddress.ip_address(ip).version
    tool = "iptables" if family == 4 else "ip6tables"
    chain = IPTABLES_CHAIN if family == 4 else IPTABLES6_CHAIN
    ensure_iptables_chain(family)
    # ¿ya está?
    try:
        out = run([tool, "-S", chain], capture=True).stdout
        if f"-s {ip} -j DROP" in out:
            log(f"[SKIP] Ya estaba bloqueada: {ip}")
            return
        run([tool, "-A", chain, "-s", ip, "-j", "DROP", "-m", "comment", "--comment", "dos-guard"])
        log(f"[OK] Bloqueada (iptables) {ip}")
    except Exception as e:
        log(f"[ERR] iptables add {ip}: {e}")

# ---------- Operaciones de alto nivel ----------
def block_ips(ips: Set[str], allowlist: Set[str]):
    # filtra whitelist
    to_block = [ip for ip in ips if ip not in allowlist]
    if not to_block:
        log("No hay IPs para bloquear (todas en whitelist o inválidas).")
        return

    v4, v6 = split_valid_ips(set(to_block))

    have_ipset = False
    if program_exists("ipset"):
        ok4 = ensure_ipset(4)
        ok6 = ensure_ipset(6)
        ensure_iptables_chain(4)
        ensure_iptables_chain(6)
        have_ipset = ok4 or ok6

    if have_ipset:
        for ip in v4 | v6:
            ipset_add(ip)
    else:
        # Fallback con iptables por IP
        for ip in v4 | v6:
            block_with_iptables(ip)

def unblock_ip(ip: str):
    # Intenta quitar de ipset; si no, de iptables fallback
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        log(f"[ERR] IP inválida para desbloquear: {ip}")
        return
    if program_exists("ipset"):
        name = IPSET_NAME_V4 if ipaddress.ip_address(ip).version == 4 else IPSET_NAME_V6
        run(["ipset", "del", name, ip], check=False)
        log(f"[OK] Eliminada de ipset {name}: {ip}")
    # También intenta quitar reglas específicas del fallback
    tool = "iptables" if ipaddress.ip_address(ip).version == 4 else "ip6tables"
    chain = IPTABLES_CHAIN if ipaddress.ip_address(ip).version == 4 else IPTABLES6_CHAIN
    try:
        # Elimina todas las instancias exactas de -s ip -j DROP
        while True:
            run([tool, "-D", chain, "-s", ip, "-j", "DROP"], check=True)
            log(f"[OK] Eliminada regla específica de {tool}: {ip}")
    except subprocess.CalledProcessError:
        pass  # no había más

def list_blocked():
    if program_exists("ipset"):
        for name in [IPSET_NAME_V4, IPSET_NAME_V6]:
            try:
                out = run(["ipset", "list", name], capture=True).stdout
                print(out)
            except subprocess.CalledProcessError:
                print(f"(ipset {name} no existe)")
    else:
        for tool, chain in [("iptables", IPTABLES_CHAIN), ("ip6tables", IPTABLES6_CHAIN)]:
            try:
                out = run([tool, "-S", chain], capture=True).stdout
                print(f"=== {tool} {chain} ===\n{out}")
            except subprocess.CalledProcessError:
                print(f"(cadena {chain} no existe en {tool})")

# ---------- Whitelist segura ----------
def build_allowlist() -> Set[str]:
    wl = set(cargar_ips(ARCHIVO_WHITELIST))
    local_ips = get_local_ips()
    gw = get_gateway_ip()
    wl |= local_ips
    if gw:
        wl.add(gw)
    return wl

# ---------- CLI ----------
def print_menu(ips_detectadas: Set[str], whitelist: Set[str]):
    print("\n=== IPs detectadas (filtradas por whitelist) ===")
    if not ips_detectadas:
        print("(vacío)")
    else:
        for i, ip in enumerate(sorted(ips_detectadas), 1):
            print(f"{i}. {ip}")
    print("\nWhitelist (no se bloquearán nunca):")
    for ip in sorted(whitelist):
        print(f" - {ip}")
    print("\nOpciones:")
    print("  [números separados por coma]  -> bloquear esas IPs")
    print("  w <IP>                         -> agregar IP a whitelist")
    print("  u <IP>                         -> desbloquear IP")
    print("  l                              -> listar bloqueos actuales")
    print("  a                              -> bloquear TODAS las IPs detectadas")
    print("  q                              -> salir")

def interactive():
    wl = build_allowlist()
    detectadas = cargar_ips(ARCHIVO_IPS)
    # quitar whitelist
    detectadas = {ip for ip in detectadas if ip not in wl}

    if not detectadas:
        print("No hay IPs para bloquear (todas en whitelist o archivo vacío).")
        return

    while True:
        print_menu(detectadas, wl)
        opcion = input("\nIngrese opción: ").strip()

        if opcion.lower() == "q":
            print("Saliendo.")
            break
        elif opcion.lower() == "l":
            list_blocked()
        elif opcion.lower() == "a":
            block_ips(detectadas, wl)
            detectadas.clear()
        elif opcion.startswith("w "):
            ip = opcion[2:].strip()
            try:
                ipaddress.ip_address(ip)
                append_ip(ARCHIVO_WHITELIST, ip)
                wl.add(ip)
                detectadas.discard(ip)
                log(f"[OK] Añadida a whitelist: {ip}")
            except ValueError:
                print("IP inválida.")
        elif opcion.startswith("u "):
            ip = opcion[2:].strip()
            unblock_ip(ip)
            log(f"[OK] Desbloqueada: {ip}")
        else:
            # números por coma
            try:
                indices = [int(x.strip()) for x in opcion.split(",") if x.strip()]
                seleccionadas = []
                ordered = sorted(detectadas)
                for idx in indices:
                    if 1 <= idx <= len(ordered):
                        seleccionadas.append(ordered[idx-1])
                if seleccionadas:
                    block_ips(set(seleccionadas), wl)
                    for ip in seleccionadas:
                        detectadas.discard(ip)
                else:
                    print("No se seleccionaron índices válidos.")
            except ValueError:
                print("Entrada no válida.")

def main():
    if not is_root():
        print("Este script debe ejecutarse como root (sudo).")
        sys.exit(1)

    # Soporta flags rápidas:
    #   --auto       Bloquea todas las IPs detectadas (respetando whitelist) y sale
    #   --list       Lista bloqueos actuales y sale
    #   --unblock IP Desbloquea IP y sale
    if len(sys.argv) > 1:
        if sys.argv[1] == "--list":
            list_blocked()
            return
        if sys.argv[1] == "--auto":
            wl = build_allowlist()
            det = {ip for ip in cargar_ips(ARCHIVO_IPS) if ip not in wl}
            block_ips(det, wl)
            return
        if sys.argv[1] == "--unblock" and len(sys.argv) == 3:
            unblock_ip(sys.argv[2])
            return

    interactive()

if __name__ == "__main__":
    main()

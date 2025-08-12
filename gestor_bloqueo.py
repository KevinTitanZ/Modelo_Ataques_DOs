import subprocess

ARCHIVO_IPS = "posibles_ataques.txt"
ARCHIVO_WHITELIST = "lista_blanca.txt"

def cargar_ips(filename):
    try:
        with open(filename, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
        return ips
    except FileNotFoundError:
        return set()

def guardar_ips(filename, ips):
    with open(filename, "w") as f:
        for ip in sorted(ips):
            f.write(ip + "\n")

def bloquear_ip(ip):
    # Ejecuta iptables para bloquear IP
    try:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True)
        print(f"Bloqueado IP: {ip}")
    except Exception as e:
        print(f"Error al bloquear {ip}: {e}")

def mostrar_menu(ips_detectadas, whitelist):
    print("\n=== IPs detectadas como posibles atacantes ===")
    for i, ip in enumerate(ips_detectadas, 1):
        print(f"{i}. {ip}")
    print("\nIPs en lista blanca (no serán bloqueadas):")
    for ip in whitelist:
        print(f" - {ip}")
    print("\nOpciones:")
    print("  [números separados por coma] para bloquear esas IPs")
    print("  w [IP] para agregar IP a lista blanca")
    print("  q para salir sin bloquear")

def main():
    ips_detectadas = cargar_ips(ARCHIVO_IPS)
    whitelist = cargar_ips(ARCHIVO_WHITELIST)

    # Filtrar ips detectadas quitando las de whitelist
    ips_para_bloquear = [ip for ip in ips_detectadas if ip not in whitelist]

    if not ips_para_bloquear:
        print("No hay IPs para bloquear (todas están en lista blanca o no hay detectadas).")
        return

    while True:
        mostrar_menu(ips_para_bloquear, whitelist)
        opcion = input("\nIngrese opción: ").strip()

        if opcion.lower() == 'q':
            print("Saliendo sin bloquear.")
            break

        elif opcion.startswith('w '):
            # Agregar IP a lista blanca
            nueva_ip = opcion[2:].strip()
            if nueva_ip:
                whitelist.add(nueva_ip)
                guardar_ips(ARCHIVO_WHITELIST, whitelist)
                print(f"IP {nueva_ip} agregada a lista blanca.")
                # Remover de ips_para_bloquear si está ahí
                if nueva_ip in ips_para_bloquear:
                    ips_para_bloquear.remove(nueva_ip)
            else:
                print("No especificó IP válida para agregar a lista blanca.")

        else:
            # Intentar interpretar como números separados por coma
            try:
                indices = [int(x.strip()) for x in opcion.split(",")]
                seleccionadas = []
                for idx in indices:
                    if 1 <= idx <= len(ips_para_bloquear):
                        seleccionadas.append(ips_para_bloquear[idx - 1])
                    else:
                        print(f"Índice {idx} fuera de rango.")
                if seleccionadas:
                    for ip in seleccionadas:
                        bloquear_ip(ip)
                    # Quitar las bloqueadas de la lista para no repetir
                    ips_para_bloquear = [ip for ip in ips_para_bloquear if ip not in seleccionadas]
                    if not ips_para_bloquear:
                        print("No quedan más IPs para bloquear.")
                        break
                else:
                    print("No se seleccionaron IPs válidas.")
            except ValueError:
                print("Entrada no válida, ingrese números separados por coma, 'w IP' para whitelist o 'q' para salir.")

if __name__ == "__main__":
    main()

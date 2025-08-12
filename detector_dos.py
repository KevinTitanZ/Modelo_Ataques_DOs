import joblib
from scapy.all import sniff, IP, TCP, UDP
import os

# Carga el modelo entrenado
modelo = joblib.load("modelo_deteccion_dos.pkl")

ARCHIVO_IPS = "posibles_ataques.txt"

def guardar_ip(ip):
    ips = set()
    if os.path.exists(ARCHIVO_IPS):
        with open(ARCHIVO_IPS, "r") as f:
            ips = set(line.strip() for line in f if line.strip())
    if ip not in ips:
        ips.add(ip)
        with open(ARCHIVO_IPS, "w") as f:
            for ip_guardada in sorted(ips):
                f.write(ip_guardada + "\n")

def extraer_caracteristicas(paquete):
    # Extrae características simples del paquete para el modelo
    # (ajusta según las que usaste en entrenamiento)
    src_port = paquete.sport if hasattr(paquete, 'sport') else 0
    dst_port = paquete.dport if hasattr(paquete, 'dport') else 0
    proto = 0
    if TCP in paquete:
        proto = 6
    elif UDP in paquete:
        proto = 17
    length = len(paquete)
    # Por ejemplo: 6 características (ajusta si tienes más)
    return [src_port, dst_port, proto, length, 0, 0]  # Ajusta '0,0' si tienes otras features

def procesar_paquete(paquete):
    if IP in paquete:
        features = extraer_caracteristicas(paquete)
        try:
            prediccion = modelo.predict([features])[0]
        except Exception as e:
            print(f"Error en predicción: {e}")
            return

        ip_origen = paquete[IP].src
        if prediccion == 1:
            print(f"⚠️ Posible ataque DoS detectado desde IP: {ip_origen}")
            guardar_ip(ip_origen)
        else:
            print(f"Tráfico normal desde IP: {ip_origen}")

print("📡 Monitoreando tráfico en tiempo real... (Ctrl+C para detener)")
sniff(prn=procesar_paquete, store=False)

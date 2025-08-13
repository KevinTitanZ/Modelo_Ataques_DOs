import os
import time
import socket
import joblib
from collections import deque, defaultdict
from datetime import datetime, timedelta

from scapy.all import sniff, IP, TCP, UDP, conf

# ---------- Carga modelo + metadatos ----------
MODEL_PATH = "artefactos/modelo_rf_calibrado.pkl"  # ajusta si usas otro
META_PATH  = "artefactos/metadata.pkl"

clf = joblib.load(MODEL_PATH)
meta = joblib.load(META_PATH)
FEATURES = meta.get("features", [])   # mismo orden del entrenamiento
THRESH_F1 = float(meta.get("umbral", 0.5))

# Umbrales con histeresis
T_HIGH = max(THRESH_F1, 0.8)  # subir si priorizas FP muy bajos
T_LOW  = 0.4

# Ventana de decisión
WIN_SECS = 1                   # tamaño de ventana por host
HITS_FOR_ALERT = 3             # disparar si 3 de 5 ventanas recientes
MAJORITY_LEN = 5               # historial para mayoría/histeresis
COOLDOWN_SECS = 60             # no alertar otra vez a la misma IP antes de esto

ARCHIVO_IPS = "posibles_ataques.txt"

# ---------- Infraestructura/allowlist ----------
def get_local_ips():
    # IPs locales del host (rápido/ligero)
    ips = set()
    try:
        hostname = socket.gethostname()
        ips.add(socket.gethostbyname(hostname))
    except:
        pass
    # También IP de ruta por defecto (interfaz principal)
    try:
        gw = conf.route.route("0.0.0.0")[1]
        if gw and isinstance(gw, str):
            ips.add(gw)  # realmente conf.route.route devuelve gateway
    except:
        pass
    return {ip for ip in ips if ip and ip != "0.0.0.0"}

def get_gateway_ip():
    try:
        gw = conf.route.route("0.0.0.0")[2]  # [2] suele ser la IP gateway
        if isinstance(gw, str):
            return gw
    except:
        pass
    return None

LOCAL_IPS = get_local_ips()
GATEWAY_IP = get_gateway_ip()

ALLOWLIST = set()
ALLOWLIST.update(LOCAL_IPS)
if GATEWAY_IP:
    ALLOWLIST.add(GATEWAY_IP)

# Permite añadir manualmente (DNS, etc.)
MANUAL_ALLOW = os.getenv("ALLOWLIST_EXTRA", "")
if MANUAL_ALLOW:
    for token in MANUAL_ALLOW.split(","):
        t = token.strip()
        if t:
            ALLOWLIST.add(t)

print(f"[INFO] Allowlist: {sorted(ALLOWLIST)}")

# ---------- Estados en memoria ----------
class HostState:
    def __init__(self):
        self.win_start = None
        self.buffer = deque()      # paquetes en ventana (timestamps y flags mínimos)
        self.scores = deque(maxlen=MAJORITY_LEN)  # últimas probabilidades
        self.hits = deque(maxlen=MAJORITY_LEN)    # últimas decisiones (0/1)
        self.last_alert_ts = 0

    def reset_window(self, now):
        self.win_start = now
        self.buffer.clear()

states = defaultdict(HostState)

# ---------- Utilidades de features (deben reflejar tu entrenamiento) ----------

WELL_KNOWN_MAX = 1023
REGISTERED_MAX = 49151

def port_cat(p):
    if not p:
        return 0
    if p <= WELL_KNOWN_MAX:
        return 1
    if p <= REGISTERED_MAX:
        return 2
    return 3

def extract_packet_features(pkt):
    """
    Devuelve un dict con features por PAQUETE que luego agregaremos por ventana.
    Debe ser consistente con el modelo entrenado.
    """
    f = {
        "frame_len": len(pkt),
        "is_tcp": 1 if TCP in pkt else 0,
        "is_udp": 1 if UDP in pkt else 0,
        "is_icmp": 1 if pkt.haslayer("ICMP") else 0,
        "tcp_syn": 0, "tcp_ack": 0, "tcp_rst": 0, "tcp_fin": 0, "tcp_psh": 0, "tcp_urg": 0,
        "src_port_cat": 0, "dst_port_cat": 0,
    }
    if TCP in pkt:
        tcp = pkt[TCP]
        f["tcp_syn"] = 1 if tcp.flags & 0x02 else 0
        f["tcp_ack"] = 1 if tcp.flags & 0x10 else 0
        f["tcp_rst"] = 1 if tcp.flags & 0x04 else 0
        f["tcp_fin"] = 1 if tcp.flags & 0x01 else 0
        f["tcp_psh"] = 1 if tcp.flags & 0x08 else 0
        f["tcp_urg"] = 1 if tcp.flags & 0x20 else 0
        f["src_port_cat"] = port_cat(int(tcp.sport))
        f["dst_port_cat"] = port_cat(int(tcp.dport))
    elif UDP in pkt:
        udp = pkt[UDP]
        f["src_port_cat"] = port_cat(int(udp.sport))
        f["dst_port_cat"] = port_cat(int(udp.dport))
    return f

def aggregate_window_features(packets):
    """
    Agrega por ventana (1s por defecto). Debe producir EXACTAMENTE
    las columnas de FEATURES que espera el modelo.
    """
    # Contadores en ventana
    pkts = len(packets)
    bytes_sum = sum(p["frame_len"] for p in packets)
    syn_sum = sum(p["tcp_syn"] for p in packets)
    ack_sum = sum(p["tcp_ack"] for p in packets)
    rst_sum = sum(p["tcp_rst"] for p in packets)
    fin_sum = sum(p["tcp_fin"] for p in packets)

    # Promedios simples
    frame_len = (bytes_sum / pkts) if pkts else 0
    is_tcp = 1 if any(p["is_tcp"] for p in packets) else 0
    is_udp = 1 if any(p["is_udp"] for p in packets) else 0
    is_icmp = 1 if any(p["is_icmp"] for p in packets) else 0

    # Port categories (tomamos la moda simple o el máximo “tipo” visto)
    src_port_cat = max((p["src_port_cat"] for p in packets), default=0)
    dst_port_cat = max((p["dst_port_cat"] for p in packets), default=0)

    syn_ack_ratio_win = (syn_sum + 1) / (ack_sum + 1)

    # Construye en el MISMO ORDEN de FEATURES
    feat_row = {
        "frame_len": frame_len,
        "is_tcp": is_tcp, "is_udp": is_udp, "is_icmp": is_icmp,
        "tcp_syn": 0, "tcp_ack": 0, "tcp_rst": 0, "tcp_fin": 0, "tcp_psh": 0, "tcp_urg": 0,
        "src_port_cat": src_port_cat, "dst_port_cat": dst_port_cat,
        "pkts": pkts, "bytes_sum": bytes_sum, "syn_sum": syn_sum, "ack_sum": ack_sum, "rst_sum": rst_sum, "fin_sum": fin_sum,
        "syn_ack_ratio_win": syn_ack_ratio_win,
    }

    # Para flags agregadas por ventana: podemos usar sumas o indicar presencia;
    # aquí mantenemos 0/1 como "hubo en la ventana" para no romper el orden esperado
    if pkts:
        # presencia de flags en la ventana (0/1)
        for k in ["tcp_syn","tcp_ack","tcp_rst","tcp_fin","tcp_psh","tcp_urg"]:
            feat_row[k] = 1 if any(p[k] for p in packets) else 0

    # Devuelve lista en el mismo orden que FEATURES
    return [feat_row[c] if c in feat_row else 0 for c in FEATURES]

# ---------- Persistencia de IPs sospechosas ----------
def guardar_ip(ip):
    # Evita reescribir todo el archivo si no hay cambios
    existing = set()
    if os.path.exists(ARCHIVO_IPS):
        with open(ARCHIVO_IPS, "r") as f:
            existing = {line.strip() for line in f if line.strip()}
    if ip not in existing:
        with open(ARCHIVO_IPS, "a") as f:
            f.write(ip + "\n")

# ---------- Lógica de decisión con histeresis ----------
def post_decision(ip, proba, state: HostState):
    now = time.time()

    # Allowlist: nunca alertar salvo evidencia MUY fuerte y sostenida
    if ip in ALLOWLIST:
        strong = (proba >= 0.95)
        if strong:
            state.scores.append(proba)
            state.hits.append(1)
            if sum(state.hits) >= HITS_FOR_ALERT and (now - state.last_alert_ts > COOLDOWN_SECS):
                state.last_alert_ts = now
                return True
        else:
            state.scores.append(proba)
            state.hits.append(0)
        return False

    # Histeresis para el resto
    if proba >= T_HIGH:
        state.hits.append(1)
    elif proba <= T_LOW:
        state.hits.append(0)
    else:
        # zona gris: usa mayoría reciente
        state.hits.append(1 if sum(state.hits) >= (len(state.hits) // 2 + 1) else 0)

    # Alertar si alcanzó N hits recientes y respeta cooldown
    if sum(state.hits) >= HITS_FOR_ALERT and (now - state.last_alert_ts > COOLDOWN_SECS):
        state.last_alert_ts = now
        return True
    return False

# ---------- Procesamiento por paquete ----------
def procesar_paquete(pkt):
    if IP not in pkt:
        return

    ip_src = pkt[IP].src

    # Gestionar ventana por src
    st = states[ip_src]
    now = time.time()

    # Inicializa/rota ventana
    if st.win_start is None or (now - st.win_start) >= WIN_SECS:
        # cerrar ventana anterior -> evaluar
        if st.buffer:
            feats = aggregate_window_features(list(st.buffer))
            try:
                proba = float(clf.predict_proba([feats])[0][1])
            except Exception as e:
                print(f"[ML] Error predict_proba: {e}")
                proba = 0.0
            st.scores.append(proba)

            # Decisión con histeresis/allowlist
            if post_decision(ip_src, proba, st):
                print(f"⚠️  {datetime.now()} ALERTA: posible DoS desde {ip_src} (p={proba:.3f})")
                guardar_ip(ip_src)
            else:
                # Log ligero (si quieres descomentar)
                # print(f"[OK] {ip_src} p={proba:.3f}")
                pass

        # Nueva ventana
        st.reset_window(now)

    # Agregar paquete a la ventana corriente
    pkt_feats = extract_packet_features(pkt)
    st.buffer.append(pkt_feats)

# ---------- Sniffer ----------
print("📡 Monitoreando tráfico en tiempo real... (Ctrl+C para detener)")
# BPF filter: solo IP, evita broadcast/ARP/MDNS/LLMNR (ajusta a tu red)
bpf = "ip and not arp and not (udp port 5353) and not (udp port 5355)"
# Si quieres solo tu interfaz principal: iface=conf.iface
sniff(prn=procesar_paquete, store=False, filter=bpf)

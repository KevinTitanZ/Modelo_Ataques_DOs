import json
import numpy as np
import pandas as pd
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (classification_report, average_precision_score,
                             precision_recall_curve, confusion_matrix)
from sklearn.calibration import CalibratedClassifierCV
import joblib

# ---------- Utilidades ----------
WELL_KNOWN_MAX = 1023
REGISTERED_MAX = 49151

def safe_int(x, default=0):
    try:
        return int(x)
    except:
        return default

def parse_bool_flag(flags_dict, key):
    # flags_dict puede ser un dict de Wireshark (tcp.flags_tree)
    try:
        v = flags_dict.get(key, '0')
        return 1 if str(v) in ('1', 'True', 'true') else 0
    except:
        return 0

# ---------- Carga y extracción de features por paquete ----------
def cargar_datos(archivo_json, etiqueta):
    with open(archivo_json, "r") as f:
        datos = json.load(f)

    registros = []
    for pkt in datos:
        capa = pkt["_source"]["layers"]

        # Campos base
        frame = capa.get("frame", {})
        frame_len = safe_int(frame.get("frame.len", 0))
        proto_str = frame.get("frame.protocols", "")

        # Timestamps (si existen)
        t = frame.get("frame.time_epoch")
        ts = float(t) if t is not None else np.nan

        ip = capa.get("ip", {})
        ip_src = ip.get("ip.src", "0.0.0.0")
        ip_dst = ip.get("ip.dst", "0.0.0.0")

        tcp = capa.get("tcp", {})
        udp = capa.get("udp", {})

        # Puertos crudos (NO usaremos como features, sólo para derivadas)
        tcp_sport = safe_int(tcp.get("tcp.srcport", 0))
        tcp_dport = safe_int(tcp.get("tcp.dstport", 0))
        udp_sport = safe_int(udp.get("udp.srcport", 0))
        udp_dport = safe_int(udp.get("udp.dstport", 0))

        src_port = tcp_sport or udp_sport
        dst_port = tcp_dport or udp_dport

        # Flags TCP
        flags_tree = tcp.get("tcp.flags_tree", {})
        syn = parse_bool_flag(flags_tree, "tcp.flags.syn")
        ack = parse_bool_flag(flags_tree, "tcp.flags.ack")
        rst = parse_bool_flag(flags_tree, "tcp.flags.reset")
        fin = parse_bool_flag(flags_tree, "tcp.flags.fin")
        psh = parse_bool_flag(flags_tree, "tcp.flags.push")
        urg = parse_bool_flag(flags_tree, "tcp.flags.urg")

        # Proto one-hot
        is_tcp = 1 if "tcp" in proto_str else 0
        is_udp = 1 if "udp" in proto_str else 0
        is_icmp = 1 if "icmp" in proto_str else 0

        # Derivadas de puertos (categorías, no IDs)
        
        src_port_cat = (
            0 if src_port == 0 else
            1 if src_port <= WELL_KNOWN_MAX else
            2 if src_port <= REGISTERED_MAX else 3
        )
        dst_port_cat = (
            0 if dst_port == 0 else
            1 if dst_port <= WELL_KNOWN_MAX else
            2 if dst_port <= REGISTERED_MAX else 3
        )

        registros.append({
            # Identificadores (NO entran al modelo, sólo para agrupación/inspección)
            "ip_src_str": ip_src,
            "ip_dst_str": ip_dst,
            "timestamp": ts,

            # Features
            "frame_len": frame_len,
            "is_tcp": is_tcp,
            "is_udp": is_udp,
            "is_icmp": is_icmp,
            "tcp_syn": syn,
            "tcp_ack": ack,
            "tcp_rst": rst,
            "tcp_fin": fin,
            "tcp_psh": psh,
            "tcp_urg": urg,
            "src_port_cat": src_port_cat,
            "dst_port_cat": dst_port_cat,

            "label": etiqueta
        })

    return pd.DataFrame(registros)

# ---------- Carga datasets ----------
df_bueno = cargar_datos("trafico_bueno.json", 0)
df_malo = cargar_datos("trafico_malo.json", 1)
df = pd.concat([df_bueno, df_malo], ignore_index=True)

# Limpieza básica
df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

# ---------- (Opcional) Agregar ratios simples por src_ip y ventana corta ----------
# Esto ayuda a detectar ráfagas (SYN, etc.). Ventana simple por segundos si hay timestamp.

#Verifica si tus paquetes tienen marca de tiempo (timestamp) válida.

# Si no, se crean columnas neutras para evitar errores.
if df["timestamp"].notna().any():
    # ventana de 1s por src

#Agrupa paquetes por IP de origen y ventana de tiempo.

#Calcula métricas por ventana:
#pkts → número de paquetes enviados
#bytes_sum → suma de bytes enviados
#syn_sum, ack_sum, rst_sum, fin_sum → cuántos paquetes con cada bandera TCP
#Esto es clave para detectar ráfagas o ataques DoS, porque muchos ataques envían muchos paquetes
    df["t_win"] = (df["timestamp"] // 1).astype(int)
    g = df.groupby(["ip_src_str", "t_win"])
    burst = g.agg(
        pkts=("frame_len", "count"),
        bytes_sum=("frame_len", "sum"),
        syn_sum=("tcp_syn", "sum"),
        ack_sum=("tcp_ack", "sum"),
        rst_sum=("tcp_rst", "sum"),
        fin_sum=("tcp_fin", "sum"),
    ).reset_index()

    # Mapear las métricas de vuelta al dataframe
    #Así, cada paquete ahora “conoce” cuántos paquetes y bytes hubo de su IP en ese segundo.
    df = df.merge(burst, on=["ip_src_str", "t_win"], how="left")
    
    # Ratios
#Un ratio muy alto de SYN/ACK suele indicar un SYN Flood, típico en ataques DoS.
    df["syn_ack_ratio_win"] = (df["syn_sum"] + 1) / (df["ack_sum"] + 1)
else:
    # Si no hay timestamp, crea columnas neutras
    df["pkts"] = 1
    df["bytes_sum"] = df["frame_len"]
    df["syn_sum"] = df["tcp_syn"]
    df["ack_sum"] = df["tcp_ack"]
    df["rst_sum"] = df["tcp_rst"]
    df["fin_sum"] = df["tcp_fin"]
    df["syn_ack_ratio_win"] = (df["syn_sum"] + 1) / (df["ack_sum"] + 1)

# ---------- Selección de features (sin IPs/puertos crudos) ----------

#tamaño del paquete, qué protocolo usa, categoría de puertos (bien conocidos, registrados, dinámicos)
#métricas por ventana de tiempo
#ratio SYN/ACK que ayuda a detectar flood

FEATURES = [
    "frame_len",
    "is_tcp", "is_udp", "is_icmp",
    "tcp_syn", "tcp_ack", "tcp_rst", "tcp_fin", "tcp_psh", "tcp_urg",
    "src_port_cat", "dst_port_cat",
    "pkts", "bytes_sum", "syn_sum", "ack_sum", "rst_sum", "fin_sum",
    "syn_ack_ratio_win",
]

X = df[FEATURES].astype(float)
y = df["label"].astype(int)

# ---------- Split SIN fuga (agrupar por host de origen) ----------
#Se separa 80% entrenamiento, 20% prueba.
#Se agrupa por IP para que las mismas IP no estén en ambos conjuntos.
groups = df["ip_src_str"].astype(str)
gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
train_idx, test_idx = next(gss.split(X, y, groups=groups))

X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

# ---------- Modelo + calibración ----------
base_rf = RandomForestClassifier(
    n_estimators=400,
    max_depth=None,
    min_samples_leaf=2,
    max_features="sqrt",
    class_weight="balanced",
    n_jobs=-1,
    random_state=42
)

# Calibramos para umbrales significativos (isotónica suele ir bien con RF)
clf = CalibratedClassifierCV(base_rf, cv=3, method="isotonic")

#x mtericas, y etiquetas
clf.fit(X_train, y_train)
# ---------- Evaluación ----------
proba_test = clf.predict_proba(X_test)[:, 1]
pred_default = (proba_test >= 0.5).astype(int)

print("\n== Reporte con umbral 0.5 ==")
print(classification_report(y_test, pred_default, digits=3))
print("PR-AUC:", round(average_precision_score(y_test, proba_test), 4))
print("Matriz de confusión (0.5):")
print(confusion_matrix(y_test, pred_default))

# Elegir umbral por F1 o por recall con límite de FPR
prec, rec, thr = precision_recall_curve(y_test, proba_test)
f1 = 2 * (prec * rec) / (prec + rec + 1e-9)
best_idx = np.nanargmax(f1)
best_thr = thr[best_idx] if best_idx < len(thr) else 0.5

print(f"\nUmbral elegido por F1: {best_thr:.3f}")

pred_best = (proba_test >= best_thr).astype(int)
print("\n== Reporte con umbral óptimo (F1) ==")
print(classification_report(y_test, pred_best, digits=3))
print("Matriz de confusión (F1):")
print(confusion_matrix(y_test, pred_best))

# ---------- Guardado de artefactos ----------
Path("artefactos").mkdir(exist_ok=True)
joblib.dump(clf, "artefactos/modelo_rf_calibrado.pkl")
meta = {
    "features": FEATURES,
    "umbral": float(best_thr),
    "nota": "Modelo RandomForest calibrado (isotonic). No usar IPs/puertos crudos.",
}
joblib.dump(meta, "artefactos/metadata.pkl")
print("\nModelo y metadatos guardados en /artefactos")

#Este código lee datos de red, extrae características, 
# entrena un Random Forest calibrado para detectar ataques, 
# lo evalúa, busca el mejor umbral de decisión y lo guarda listo para usar en producción.
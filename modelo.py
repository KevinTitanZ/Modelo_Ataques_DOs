import json
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Función para cargar y procesar datos desde un JSON
def cargar_datos(archivo_json, etiqueta):
    with open(archivo_json, "r") as f:
        datos = json.load(f)

    registros = []
    for pkt in datos:
        capa = pkt["_source"]["layers"]

        # Extraemos características relevantes
        frame_len = int(capa["frame"]["frame.len"])
        proto = capa["frame"]["frame.protocols"]

        ip_src = capa.get("ip", {}).get("ip.src", "0.0.0.0")
        ip_dst = capa.get("ip", {}).get("ip.dst", "0.0.0.0")

        src_port = int(capa.get("udp", {}).get("udp.srcport", 0) or capa.get("tcp", {}).get("tcp.srcport", 0))
        dst_port = int(capa.get("udp", {}).get("udp.dstport", 0) or capa.get("tcp", {}).get("tcp.dstport", 0))

        registros.append({
            "frame_len": frame_len,
            "proto": 1 if "tcp" in proto else 2 if "udp" in proto else 0,
            "src_port": src_port,
            "dst_port": dst_port,
            "ip_src": sum([int(x) << (8*i) for i, x in enumerate(reversed(ip_src.split(".")))]),
            "ip_dst": sum([int(x) << (8*i) for i, x in enumerate(reversed(ip_dst.split(".")))]),
            "label": etiqueta
        })

    return pd.DataFrame(registros)

# Cargamos tráfico bueno y malo
df_bueno = cargar_datos("trafico_bueno.json", 0)
df_malo = cargar_datos("trafico_malo.json", 1)

# Unimos todo
df = pd.concat([df_bueno, df_malo], ignore_index=True)

# Datos de entrada y salida
X = df.drop(columns=["label"])
y = df["label"]

# División de datos
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Entrenamos el modelo
modelo = RandomForestClassifier(n_estimators=100, random_state=42)
modelo.fit(X_train, y_train)

# Evaluación
y_pred = modelo.predict(X_test)
print(classification_report(y_test, y_pred))

# Guardamos el modelo
joblib.dump(modelo, "modelo_deteccion_dos.pkl")
print("Modelo guardado como modelo_deteccion_dos.pkl")

# Modelo_Ataques_DOs

source venv/bin/activate # solo si es necesario meterse a descargar algo mas

# Comenzamos con esto para entrenar el modelo:
python modelo.py

# PARA HACER FUNCIONAR EL CODIGO
sudo $(which python) detector_dos.py

# o
sudo /home/kevin/Documentos/Proyecto/venv/bin/python detector_dos.py


# PARA VER LAS IP ATACANTES
sudo python gestor_bloqueo.py

# Para atacar
sudo hping3 -S -p 80 -c 500 --rand-source 192.168.1.50

    Clase 0 = Tráfico normal

        precision = 0.99: casi siempre que dijo “normal” tenía razón.

        recall = 0.92: detectó el 92% de todo el tráfico realmente normal.

        f1-score = 0.95: balance muy bueno.

    Clase 1 = Tráfico malo (ataque DoS)

        precision = 0.89: de cada 100 veces que dijo “ataque”, 89 eran de verdad ataque.

        recall = 0.99: detectó prácticamente todos los ataques reales.

        f1-score = 0.94: balance muy bueno, aunque un poco menos preciso que para el tráfico normal.

    accuracy = 0.95 → El modelo acertó en el 95% de los casos totales.

#  Por si se bloquea todas las redes:
sudo iptables -F    
sudo iptables -X    
sudo iptables -t nat -F   
sudo iptables -t mangle -F
sudo iptables -P INPUT ACCEPT    
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

# Exposicion
                                                            |
------------------------------------------------------------------------------ |
| **ACK** | 1                   | ACK activo → Este paquete está **reconociendo** la recepción de datos previos. |
| **SYN** | 0                   | SYN no activo → Este paquete **no está iniciando** una nueva conexión.         |
| **FIN** | 0                   | FIN no activo → Este paquete **no está cerrando** la conexión.                 |
| **RST** | 0                   | RST no activo → Este paquete **no está reiniciando** la conexión por error.    |


# Para detección de ataques DoS

Muchos ataques usan patrones anormales de flags:

# SYN Flood: muchos paquetes con SYN=1 y ACK=0.

# RST Flood: muchos paquetes con RST=1.

# ACK Flood: muchos ACK fuera de contexto.

Observando las banderas puedes identificar patrones sospechosos en el tráfico.
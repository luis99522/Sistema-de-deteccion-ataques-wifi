Proyecto cybersen detector: 

Sistema de Detección de Intrusiones WiFi con Machine Learning Detecta ataques en tiempo real mediante el análisis pasivo de tramas 802.11.

¿Qué puede detectar?
Deauth Attack → Intentos de desconectar forzosamente dispositivos de la red.

Beacon Flood → Inundación de redes falsas para confundir a los usuarios.

Rogue AP → Puntos de acceso maliciosos que imitan redes legítimas.

Requisitos
Hardware
Tarjeta WiFi compatible con modo monitor (ejemplo: Alfa AWUS036ACH, chipsets Atheros/Ralink).

Laptop con Linux (Ubuntu, Kali, Parrot, etc.).

Software
Sistema operativo: Cualquier distribución Linux.

Herramientas necesarias:
sudo apt update
sudo apt install aircrack-ng python3 python3-pip

Dependencias de Python:
pip install scapy pandas scikit-learn joblib numpy colorama

Instalación
Clona el repositorio:
git clone https://github.com/luis99522/Sistema-de-deteccion-ataques-wifi/tree/main
cd cybersen-detector

Instala dependencias:
pip install -r requirements.txt

Configura tu tarjeta en modo monitor:
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up 

Estos son los pasos para ejecutar la herramienta: 

1. Captura de tráfico normal (2-3 min):
sudo python3 capture/capture_script.py --duration 180
mv data/capture.pcap data/trafico_normal_1.pcap

2. Captura durante ataque Deauth:
Terminal 1:
sudo aireplay-ng -0 50 -a [TU_BSSID] wlan1

Terminal 2:
sudo python3 capture/capture_script.py --duration 60
mv data/capture.pcap data/trafico_deauth.pcap

3. Captura Beacon Flood (opcional): Aunque seria conveniente para tener un model mejor entrenado

Terminal 1:
sudo mdk4 wlan1 b -f /tmp/ap_list.txt

Terminal 2:
sudo python3 capture/capture_script.py --duration 60
mv data/capture.pcap data/trafico_beacon_flood.pcap 

Tambien podrias hacer el mismo procedimiento pero con ataques de rogue AP para que el modelo detecte mas ataques. 

4. Extraer características:
python3 features/extract_features.py

5. Construir dataset:
python3 features/build_dataset.py

6. Entrenar modelo:
python3 model/train_model.py

7. Detección en tiempo real:
sudo python3 detection/realtime_detector.py

Estructura del proyecto:

cybersen-detector/
├── requirements.txt
├── capture/
│   └── capture_script.py
├── features/
│   ├── extract_features.py
│   └── build_dataset.py
├── model/
│   └── train_model.py
├── detection/
│   └── realtime_detector.py
└── data/

Nombres de archivo soportados:
Para que el etiquetado automático funcione, usa estos nombres:

trafico_normal.pcap, trafico_normal_1.pcap, … hasta trafico_normal_10.pcap

trafico_deauth.pcap

trafico_beacon_flood.pcap

trafico_rogue_ap.pcap

Ajuste de umbrales
Si recibes muchos falsos positivos, edita detection/realtime_detector.py

self.thresholds = {
    'deauth': {
        'min_predictions': 15,
        'confidence': 0.82,
        'cooldown': 60,
        'rate_threshold': 8
    },
    'beacon_flood': {
        'min_predictions': 12,
        'confidence': 0.75,
        'cooldown': 90,
        'rate_threshold': 30
    }
}

Troubleshooting
Error: No se encontró model.pkl → Entrena el modelo:

python3 model/train_model.py

Error: Permission denied → Ejecuta con sudo.

Error: Interfaz no está en modo monitor → Revisa configuración con iwconfig wlan0.

Error: Solo detecta “normal” → Necesitas capturar ataques reales y reentrenar el modelo.

Ejemplo de salida:

🛡️ CYBERSEN DETECTOR ACTIVADO
📡 Escuchando: wlan0
🎯 Detectando: Deauth, Beacon Flood, Rogue AP

✓ Paquetes analizados: 1500
🚨 Alertas de seguridad: 1
🛡️ Falsos positivos filtrados: 12
⚡ Velocidad: 28.5 paquetes/seg

📈 CLASIFICACIÓN DEL TRÁFICO:
  ✅ normal        | ███████████ 1275 (85.0%)
  🚨 deauth        | ██           150 (10.0%)
  ⚠️ beacon_flood  | █             75 (5.0%)

🚨 ¡ALERTA DE SEGURIDAD!
ATAQUE DEAUTH detectado
Dispositivo atacante: AA:BB:CC:DD:EE:FF
Certeza: 92%

Autor: 
Ghostblade


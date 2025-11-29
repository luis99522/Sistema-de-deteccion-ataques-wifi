CyberSen Detector
Sistema de Detección de Intrusiones WiFi con Machine Learning que identifica ataques en tiempo real mediante análisis pasivo de tramas 802.11.

¿Qué Detecta?

Deauth Attack: Desconexión forzada de dispositivos
Beacon Flood: Inundación de redes WiFi falsas
Rogue AP: Puntos de acceso maliciosos

Requisitos
Hardware

Tarjeta WiFi compatible con modo monitor (ej: Alfa AWUS036ACH, chipset Atheros/Ralink)
Laptop con Linux (Ubuntu, Kali, Parrot, etc.)

Software
bash# Sistema operativo
Linux (cualquier distribución)

# Herramientas
sudo apt update
sudo apt install aircrack-ng python3 python3-pip

# Dependencias Python
pip install scapy pandas scikit-learn joblib numpy colorama

Instalación:
bash# Clonar repositorio
git clone 
cd cybersen-detector

# Instalar dependencias
pip install -r requirements.txt

# Configurar interfaz en modo monitor
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up

Uso Rápido:
Opción 1: Launcher Automático (Recomendado)
bashsudo python3 launcher.py
# Seleccionar [1] Pipeline Completo
Opción 2: Ejecución Manual Paso a Paso
Paso 1: Capturar Tráfico
bash# Captura de tráfico NORMAL (2-3 minutos)
sudo python3 capture/capture_script.py --duration 180
mv data/capture.pcap data/trafico_normal_1.pcap

# Captura de ATAQUE DEAUTH
# Terminal 1: Lanzar ataque contra TU red
sudo aireplay-ng -0 50 -a [TU_BSSID] wlan1

# Terminal 2: Capturar durante el ataque
sudo python3 capture/capture_script.py --duration 60
mv data/capture.pcap data/trafico_deauth.pcap

# Captura de BEACON FLOOD (opcional)
# Terminal 1:
sudo mdk4 wlan1 b -f /tmp/ap_list.txt
# Terminal 2:
sudo python3 capture/capture_script.py --duration 60
mv data/capture.pcap data/trafico_beacon_flood.pcap
Paso 2: Extraer Características
bashpython3 features/extract_features.py
# Genera: *_dataset.csv por cada .pcap
Paso 3: Construir Dataset
bashpython3 features/build_dataset.py
# Genera: final_dataset.csv (dataset consolidado y balanceado)
Paso 4: Entrenar Modelo
bashpython3 model/train_model.py
# Genera: model.pkl (modelo entrenado)
Paso 5: Detectar en Tiempo Real
bashsudo python3 detection/realtime_detector.py
# Inicia detección 24/7

Estructura del Proyecto:
cybersen-detector/
├── requirements.txt            # Dependencias Python
├── capture/
│   └── capture_script.py      # Captura paquetes WiFi
├── features/
│   ├── extract_features.py    # Extrae características
│   └── build_dataset.py       # Consolida datasets
├── model/
│   └── train_model.py         # Entrena modelo ML
├── detection/
│   └── realtime_detector.py   # Detección en tiempo real
└── data/                       # Capturas y datasets (generado)

Nombres de Archivo Soportados
IMPORTANTE: Los archivos .pcap deben nombrarse así para etiquetado automático:
bash✅ trafico_normal.pcap          # Tráfico normal (una captura)
✅ trafico_normal_1.pcap        # Tráfico normal (primera captura)
✅ trafico_normal_2.pcap        # Tráfico normal (segunda captura)
   ... hasta trafico_normal_10.pcap

✅ trafico_deauth.pcap          # Ataque deauth
✅ trafico_beacon_flood.pcap    # Ataque beacon flood
✅ trafico_rogue_ap.pcap        # Ataque rogue AP
⚙️ Configuración de Umbrales
Si tienes muchos falsos positivos, edita detection/realtime_detector.py (línea ~91):
pythonself.thresholds = {
    'deauth': {
        'min_predictions': 15,    # ⬆️ Aumentar para menos FP
        'confidence': 0.82,       # ⬆️ Aumentar para más estricto
        'cooldown': 60,           # Segundos entre alertas
        'rate_threshold': 8       # Paquetes/segundo para confirmar
    },
    'beacon_flood': {
        'min_predictions': 12,
        'confidence': 0.75,
        'cooldown': 90,
        'rate_threshold': 30
    }
}
🐛 Troubleshooting
Problema: "No se encontró model.pkl"
bash# Solución: Entrena el modelo primero
python3 model/train_model.py
Problema: "Permission denied"
bash# Solución: Ejecuta con sudo
sudo python3 detection/realtime_detector.py
Problema: "Interfaz no está en modo monitor"
bash# Solución: Configura modo monitor
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up
iwconfig wlan0  # Verificar: debe decir "Mode:Monitor"
Problema: "Solo detecta 'normal', no ataques"
bash# Solución: Necesitas capturar ataques REALES
# 1. Captura tráfico normal
# 2. Simula ataques con aireplay-ng/mdk4
# 3. Captura durante el ataque
# 4. Re-entrena el modelo
📊 Ejemplo de Salida
🛡️  CYBERSEN DETECTOR ACTIVADO
════════════════════════════════════════════════════
📡 Escuchando: wlan0
🎯 Detectando: Deauth, Beacon Flood, Rogue AP
════════════════════════════════════════════════════

📊 RESUMEN DE ACTIVIDAD
────────────────────────────────────────────────────
✓ Paquetes analizados: 1500
🚨 Alertas de seguridad: 1
🛡️  Falsos positivos filtrados: 12
⚡ Velocidad: 28.5 paquetes/seg

📈 CLASIFICACIÓN DEL TRÁFICO:
  ✅ normal          | ███████████  1275 (85.0%)
  🚨 deauth          | ██            150 (10.0%)
  ⚠️ beacon_flood    | █              75 (5.0%)

🚨 ═══════════════════════════════════════════════
║ ¡ALERTA DE SEGURIDAD!
║ ATAQUE DEAUTH
║ Intento de desconectar dispositivos de la red
║ 
║ 📍 Dispositivo atacante: AA:BB:CC:DD:EE:FF
║ 🎯 Certeza: 92%
═══════════════════════════════════════════════
⚠️ Consideraciones Legales

✅ Usar en tu propia red: Legal
✅ Usar con permiso escrito: Legal
❌ Usar en redes ajenas sin permiso: ILEGAL

Este proyecto es solo para fines educativos y de defensa. El uso indebido puede ser ilegal en tu país.
🤝 Contribuciones
Pull requests son bienvenidos. Para cambios importantes, abre un issue primero.

👤 Autor
ghostblade

GitHub: @luis99522


⭐ Si este proyecto te fue útil, dale una estrella en GitHub!


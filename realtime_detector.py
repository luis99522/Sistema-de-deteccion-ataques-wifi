#!/usr/bin/env python3
"""
CyberSen Detector - Detección en tiempo real OPTIMIZADO
Detecta: Deauth, Beacon Flood y Rogue AP
Versión mejorada con detección de Beacon Flood corregida
"""
from scapy.all import *
import joblib
import pandas as pd
import time
from collections import deque, defaultdict
from datetime import datetime
import os
import warnings
warnings.filterwarnings('ignore')

class CyberSenRealTimeDetector:
    def __init__(self, model_path="model/model.pkl", interface="wlan0"):
        """
        Inicializa el detector en tiempo real
        
        Args:
            model_path: Ruta al modelo entrenado
            interface: Interfaz de red en modo monitor
        """
        self.interface = interface
        self.model_path = model_path
        
        # Cargar modelo
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Modelo no encontrado: {model_path}")
        
        self.model = joblib.load(model_path)
        
        # Cargar features si existen
        features_path = model_path.replace('.pkl', '_features.pkl')
        if os.path.exists(features_path):
            self.feature_cols = joblib.load(features_path)
        else:
            self.feature_cols = ["frame_type", "rssi", "packet_rate", "freq"]
        
        print(f"[✓] Modelo cargado: {model_path}")
        print(f"[✓] Features: {self.feature_cols}")
        
        # Ventanas de tiempo para análisis
        self.packet_times = deque(maxlen=1000)
        self.attack_history = defaultdict(lambda: deque(maxlen=25))
        
        # Contadores por MAC para detectar patrones
        self.mac_stats = defaultdict(lambda: {
            'deauth_count': 0,
            'beacon_count': 0,
            'auth_count': 0,
            'total_packets': 0,
            'first_seen': time.time(),
            'last_alert': 0,
            'last_alert_type': None,
            'beacon_times': deque(maxlen=100)  # ⭐ NUEVO: timestamps de beacons
        })
        
        # ╔═══════════════════════════════════════════════════════════════════╗
        # ║  CONFIGURACIÓN DE UMBRALES - AJUSTA AQUÍ PARA TUS NECESIDADES    ║
        # ╚═══════════════════════════════════════════════════════════════════╝
        #
        # 🎯 ¿CÓMO AJUSTAR?
        # 
        # Si tienes MUCHOS FALSOS POSITIVOS (alertas sin ataques):
        #   → AUMENTA los valores (más estricto)
        #   → Ejemplo: min_predictions de 15 a 20-25
        #
        # Si NO DETECTA ataques reales:
        #   → DISMINUYE los valores (más sensible)
        #   → Ejemplo: min_predictions de 15 a 8-10
        #
        # 📊 PARÁMETROS:
        #
        # • min_predictions: 
        #     Cuántas veces debe sospechar antes de alertar
        #     Bajo (5-8) = Rápido pero más falsas alarmas
        #     Alto (20-30) = Lento pero más preciso
        #
        # • confidence:
        #     Nivel de seguridad requerido (0.0 a 1.0)
        #     0.7 = 70% seguro
        #     0.9 = 90% seguro (más estricto)
        #
        # • cooldown:
        #     Segundos que debe esperar entre alertas del mismo tipo
        #     30 = Puede alertar cada 30 segundos
        #     180 = Solo alerta cada 3 minutos (reduce spam)
        #
        # • rate_threshold:
        #     Paquetes por segundo para considerar anormal
        #     Bajo (3-5) = Detecta ataques lentos
        #     Alto (15-30) = Solo ataques muy agresivos
        #
        # ═══════════════════════════════════════════════════════════════════
        
        self.thresholds = {
            'deauth': {
                'min_predictions': 15,      # ⬅️ AJUSTAR: Predicciones mínimas
                'confidence': 0.82,         # ⬅️ AJUSTAR: Confianza (0.0-1.0)
                'cooldown': 60,             # ⬅️ AJUSTAR: Segundos entre alertas
                'rate_threshold': 8         # ⬅️ AJUSTAR: Deauths por segundo
            },
            'beacon_flood': {
                'min_predictions': 12,      # ⬅️ AJUSTADO: Reducido (antes: 20)
                'confidence': 0.75,         # ⬅️ AJUSTADO: Reducido (antes: 0.90)
                'cooldown': 90,             # ⬅️ AJUSTAR: Segundos entre alertas
                'rate_threshold': 30,       # ⬅️ AJUSTADO: Reducido (antes: 100)
                'min_beacons': 50           # ⬅️ NUEVO: Beacons mínimos absolutos
            },
            'rogue_ap': {
                'min_predictions': 15,      # ⬅️ AJUSTAR
                'confidence': 0.88,         # ⬅️ AJUSTAR
                'cooldown': 180,            # ⬅️ AJUSTAR
                'rate_threshold': 10        # ⬅️ AJUSTAR
            }
        }
        
        # MACs inválidas que se deben ignorar (falsos positivos comunes)
        self.invalid_macs = {
            '00:00:00:00:00:00',
            'ff:ff:ff:ff:ff:ff',
            None
        }
        
        # Estadísticas generales
        self.stats = {
            'total_packets': 0,
            'alerts': 0,
            'false_positives_filtered': 0,
            'start_time': time.time(),
            'predictions': defaultdict(int)
        }
        
    def is_valid_mac(self, mac):
        """Verifica si una MAC es válida"""
        if mac in self.invalid_macs:
            return False
        if mac and mac.startswith('00:00:00'):
            return False
        return True
    
    def packet_rate(self):
        """Calcula la tasa de paquetes por segundo"""
        now = time.time()
        self.packet_times.append(now)
        
        cutoff = now - 1.0
        while self.packet_times and self.packet_times[0] < cutoff:
            self.packet_times.popleft()
        
        return len(self.packet_times)
    
    def normalize_prediction(self, prediction):
        """
        Normaliza las predicciones del modelo a solo los ataques que queremos detectar
        Convierte auth_flood y otras predicciones a normal
        """
        valid_attacks = ['deauth', 'beacon_flood', 'rogue_ap', 'normal']
        
        if prediction in valid_attacks:
            return prediction
        
        return 'normal'
    
    def should_alert(self, attack_type, src_mac):
        """
        Determina si se debe emitir una alerta
        """
        # Verificar MAC válida
        if not self.is_valid_mac(src_mac):
            self.stats['false_positives_filtered'] += 1
            return False
        
        # Verificar cooldown
        last_alert = self.mac_stats[src_mac]['last_alert']
        last_type = self.mac_stats[src_mac]['last_alert_type']
        cooldown = self.thresholds.get(attack_type, {}).get('cooldown', 60)
        
        if time.time() - last_alert < cooldown and last_type == attack_type:
            return False
        
        # Verificar historial de predicciones
        recent_predictions = list(self.attack_history[src_mac])
        
        attack_predictions = recent_predictions.count(attack_type)
        
        min_preds = self.thresholds.get(attack_type, {}).get('min_predictions', 15)
        
        if attack_predictions >= min_preds:
            if len(recent_predictions) > 0:
                confidence = attack_predictions / len(recent_predictions)
                min_conf = self.thresholds.get(attack_type, {}).get('confidence', 0.85)
                
                if confidence >= min_conf:
                    return True
        
        return False
    
    def analyze_beacon_rate(self, src_mac):
        """
        ⭐ NUEVO: Analiza la tasa de beacons de forma más precisa
        
        Returns:
            float: Beacons por segundo en ventana reciente
        """
        beacon_times = list(self.mac_stats[src_mac]['beacon_times'])
        
        if len(beacon_times) < 5:  # Necesitamos al menos 5 beacons
            return 0.0
        
        # Calcular ventana de tiempo
        time_window = beacon_times[-1] - beacon_times[0]
        
        if time_window < 0.1:  # Evitar división por cero
            return 0.0
        
        # Tasa = cantidad de beacons / tiempo
        rate = len(beacon_times) / time_window
        
        return rate
    
    def analyze_packet_pattern(self, pkt, src_mac):
        """Analiza patrones de paquetes para confirmar ataques"""
        if not self.is_valid_mac(src_mac):
            return None
        
        stats = self.mac_stats[src_mac]
        subtype = pkt[Dot11].subtype
        
        stats['total_packets'] += 1
        
        # Análisis de Deauth
        if subtype == 12:  # Deauth
            stats['deauth_count'] += 1
            time_active = time.time() - stats['first_seen']
            if time_active > 1:
                deauth_rate = stats['deauth_count'] / time_active
                if deauth_rate > self.thresholds['deauth']['rate_threshold']:
                    if stats['deauth_count'] > 20:
                        return 'deauth'
        
        # ⭐ ANÁLISIS MEJORADO DE BEACON FLOOD
        elif subtype == 8:  # Beacon
            stats['beacon_count'] += 1
            
            # Registrar timestamp del beacon
            stats['beacon_times'].append(time.time())
            
            # Calcular tasa precisa de beacons
            beacon_rate = self.analyze_beacon_rate(src_mac)
            
            # Verificar umbrales ajustados
            rate_threshold = self.thresholds['beacon_flood']['rate_threshold']
            min_beacons = self.thresholds['beacon_flood']['min_beacons']
            
            # Debug: Mostrar tasa de beacons cada 20 beacons
            if stats['beacon_count'] % 20 == 0:
                print(f"[DEBUG] MAC {src_mac[:17]}: {stats['beacon_count']} beacons, rate={beacon_rate:.2f}/s")
            
            # Condiciones para confirmar beacon flood:
            # 1. Tasa > 30 beacons/segundo
            # 2. Al menos 50 beacons totales
            if beacon_rate > rate_threshold and stats['beacon_count'] >= min_beacons:
                print(f"[!] Beacon flood detectado: {beacon_rate:.2f} beacons/s (threshold: {rate_threshold})")
                return 'beacon_flood'
        
        return None
    
    def emit_alert(self, attack_type, src_mac, details):
        """Emite una alerta de ataque detectado con mensajes claros"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        alert_info = {
            'deauth': {
                'symbol': '🚨',
                'severity': 'ALTA',
                'title': 'ATAQUE DEAUTH',
                'description': 'Intento de desconectar dispositivos de la red WiFi'
            },
            'beacon_flood': {
                'symbol': '⚠️',
                'severity': 'MEDIA',
                'title': 'ATAQUE BEACON FLOOD',
                'description': 'Inundación de redes WiFi falsas para confundir dispositivos'
            },
            'rogue_ap': {
                'symbol': '🔴',
                'severity': 'ALTA',
                'title': 'ATAQUE ROGUE AP',
                'description': 'Punto de acceso falso intentando suplantar red legítima'
            }
        }
        
        info = alert_info.get(attack_type, {
            'symbol': '⚡',
            'severity': 'MEDIA',
            'title': 'ACTIVIDAD SOSPECHOSA',
            'description': 'Comportamiento anormal detectado en la red'
        })
        
        print(f"\n{info['symbol']} ═══════════════════════════════════════════════")
        print(f"║ ¡ALERTA DE SEGURIDAD!")
        print(f"║")
        print(f"║ {info['title']}")
        print(f"║ {info['description']}")
        print(f"║")
        print(f"║ ⏰ Hora: {timestamp}")
        print(f"║ ⚠️  Nivel de riesgo: {info['severity']}")
        print(f"║ 📍 Dispositivo atacante: {src_mac}")
        print(f"║ 📶 Señal: {details.get('rssi', 'N/A')} dBm")
        print(f"║ 📊 Tráfico: {details.get('packet_rate', 'N/A')} paquetes/segundo")
        print(f"║ 🎯 Certeza: {details.get('confidence', 0)*100:.0f}%")
        
        # Info específica para beacon flood
        if attack_type == 'beacon_flood':
            beacon_rate = details.get('beacon_rate', 0)
            beacon_count = details.get('beacon_count', 0)
            print(f"║ 📡 Beacons detectados: {beacon_count}")
            print(f"║ ⚡ Tasa de beacons: {beacon_rate:.2f} beacons/segundo")
        
        print(f"║")
        print(f"║ 💡 Recomendación:")
        
        if attack_type == 'deauth':
            print(f"║    • Verifica qué dispositivos se están desconectando")
            print(f"║    • Busca el dispositivo con MAC: {src_mac} físicamente")
            print(f"║    • Considera cambiar el canal WiFi del router")
            print(f"║    • Activa protección 802.11w (PMF) en el router")
        elif attack_type == 'beacon_flood':
            print(f"║    • Ignora las nuevas redes WiFi que aparecen")
            print(f"║    • No conectes a redes desconocidas")
            print(f"║    • Mantén tu SSID oculto si es posible")
            print(f"║    • Verifica con airodump-ng: sudo airodump-ng {self.interface}")
        elif attack_type == 'rogue_ap':
            print(f"║    • NO te conectes a esa red WiFi")
            print(f"║    • Verifica el BSSID legítimo de tu red")
            print(f"║    • Alerta a otros usuarios de la red")
        
        print(f"═══════════════════════════════════════════════\n")
        
        self.stats['alerts'] += 1
        self.mac_stats[src_mac]['last_alert'] = time.time()
        self.mac_stats[src_mac]['last_alert_type'] = attack_type
    
    def predict_attack(self, pkt):
        """Predice si un paquete es parte de un ataque"""
        if not pkt.haslayer(Dot11):
            return
        
        self.stats['total_packets'] += 1
        
        try:
            subtype = pkt[Dot11].subtype
            rssi = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -70
            pr = self.packet_rate()
            freq = 2412
            
            src_mac = pkt.addr2 if pkt.addr2 else "00:00:00:00:00:00"
            
            # FILTRO 1: Ignorar MACs inválidas inmediatamente
            if not self.is_valid_mac(src_mac):
                self.stats['false_positives_filtered'] += 1
                return
            
            # Construir features
            features_dict = {
                "frame_type": subtype,
                "rssi": rssi,
                "packet_rate": pr,
                "freq": freq
            }
            
            if "retry" in self.feature_cols:
                features_dict["retry"] = 1 if pkt[Dot11].FCfield & 0x08 else 0
            if "power_mgmt" in self.feature_cols:
                features_dict["power_mgmt"] = 1 if pkt[Dot11].FCfield & 0x10 else 0
            
            features = pd.DataFrame([features_dict], columns=self.feature_cols)
            
            # Predicción
            raw_prediction = self.model.predict(features)[0]
            
            # IMPORTANTE: Normalizar predicción
            prediction = self.normalize_prediction(raw_prediction)
            
            self.stats['predictions'][prediction] += 1
            
            # Registrar en historial
            self.attack_history[src_mac].append(prediction)
            
            # Si no es normal, analizar
            if prediction != "normal":
                confirmed_attack = self.analyze_packet_pattern(pkt, src_mac)
                
                if confirmed_attack and self.should_alert(confirmed_attack, src_mac):
                    recent = list(self.attack_history[src_mac])
                    confidence = recent.count(confirmed_attack) / len(recent) if recent else 0
                    
                    details = {
                        'rssi': rssi,
                        'packet_rate': pr,
                        'confidence': confidence,
                        'subtype': subtype
                    }
                    
                    # Agregar info específica para beacon flood
                    if confirmed_attack == 'beacon_flood':
                        details['beacon_rate'] = self.analyze_beacon_rate(src_mac)
                        details['beacon_count'] = self.mac_stats[src_mac]['beacon_count']
                    
                    self.emit_alert(confirmed_attack, src_mac, details)
            
            # Mostrar estadísticas cada 100 paquetes
            if self.stats['total_packets'] % 100 == 0:
                self.print_stats()
                
        except Exception as e:
            pass
    
    def print_stats(self):
        """Imprime estadísticas del sistema en lenguaje simple"""
        uptime = time.time() - self.stats['start_time']
        pps = self.stats['total_packets'] / uptime if uptime > 0 else 0
        
        print(f"\n{'─'*60}")
        print(f"📊 RESUMEN DE ACTIVIDAD")
        print(f"{'─'*60}")
        print(f"✓ Paquetes analizados: {self.stats['total_packets']}")
        print(f"🚨 Alertas de seguridad: {self.stats['alerts']}")
        print(f"🛡️  Falsos positivos filtrados: {self.stats['false_positives_filtered']}")
        print(f"⚡ Velocidad: {pps:.1f} paquetes/seg")
        print(f"⏱️  Tiempo activo: {int(uptime)}s")
        
        if self.stats['predictions']:
            print(f"\n📈 CLASIFICACIÓN DEL TRÁFICO:")
            total = self.stats['total_packets']
            
            sorted_preds = sorted(
                self.stats['predictions'].items(),
                key=lambda x: (x[0] != 'normal', -x[1])
            )
            
            for pred_type, count in sorted_preds:
                pct = (count / total) * 100
                bar_length = int(pct / 5)
                bar = '█' * bar_length
                
                emoji = {
                    'normal': '✅',
                    'deauth': '🚨',
                    'beacon_flood': '⚠️',
                    'rogue_ap': '🔴'
                }.get(pred_type, '📊')
                
                print(f"  {emoji} {pred_type:15s} | {bar} {count:4d} ({pct:5.1f}%)")
        
        print(f"{'─'*60}\n")
    
    def start_detection(self):
        """Inicia la detección en tiempo real con manejo robusto de errores"""
        print(f"\n{'='*60}")
        print(f"🛡️  CYBERSEN DETECTOR ACTIVADO")
        print(f"{'='*60}")
        print(f"📡 Escuchando: {self.interface}")
        print(f"🧠 Modelo: {self.model_path}")
        print(f"🎯 Detectando: Deauth, Beacon Flood, Rogue AP")
        print(f"🎯 Estado: Monitoreando tráfico WiFi...")
        print(f"❌ Para detener: Presiona Ctrl+C")
        print(f"{'='*60}\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.predict_attack,
                store=False,
                monitor=True
            )
        except KeyboardInterrupt:
            print(f"\n\n{'='*60}")
            print(f"⏸️  DETECCIÓN DETENIDA POR USUARIO")
            print(f"{'='*60}")
            self.print_stats()
            print(f"✅ Sesión finalizada correctamente")
            print(f"👋 ¡Hasta pronto!\n")
        except PermissionError:
            print(f"\n❌ ERROR: Se necesitan permisos de administrador")
            print(f"💡 Ejecuta con: sudo python3 detection/realtime_detector.py\n")
        except Exception as e:
            print(f"\n❌ ERROR INESPERADO: {e}\n")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberSen Detector - Monitoreo WiFi en Tiempo Real")
    parser.add_argument("--interface", "-i", default="wlan0", help="Interfaz de red")
    parser.add_argument("--model", "-m", default="model/model.pkl", help="Modelo entrenado")
    
    args = parser.parse_args()
    
    try:
        detector = CyberSenRealTimeDetector(
            model_path=args.model,
            interface=args.interface
        )
        detector.start_detection()
    except FileNotFoundError as e:
        print(f"\n❌ {e}")
        print(f"💡 Entrena un modelo primero:")
        print(f"   python3 model/train_model.py\n")
    except Exception as e:
        print(f"\n❌ Error: {e}\n")

if __name__ == "__main__":
    main()



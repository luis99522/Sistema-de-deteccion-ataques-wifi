#!/usr/bin/env python3
"""
CyberSen Detector - Script de captura de paquetes WiFi
Optimizado para reducir falsos positivos
"""
from scapy.all import *
import os
import sys

def capture_packets(interface="wlan0", output_file="data/capture.pcap", duration=60):
    """
    Captura paquetes WiFi en modo monitor
    
    Args:
        interface: Interfaz en modo monitor
        output_file: Archivo de salida .pcap
        duration: Duración de captura en segundos
    """
    # Crear directorio data si no existe
    os.makedirs("data", exist_ok=True)
    
    print(f"[*] Iniciando captura en {interface}")
    print(f"[*] Duración: {duration} segundos")
    print(f"[*] Archivo: {output_file}")
    print(f"[*] Capturando...\n")
    
    try:
        # Captura con filtro BPF para solo 802.11
        packets = sniff(
            iface=interface,
            timeout=duration,
            monitor=True,
            store=True
        )
        
        # Guardar captura
        wrpcap(output_file, packets)
        
        print(f"\n[✓] Captura completada")
        print(f"[✓] Total de paquetes capturados: {len(packets)}")
        print(f"[✓] Guardado en: {output_file}")
        
        return True
        
    except PermissionError:
        print("[!] Error: Se requieren permisos de root/sudo")
        print("[!] Ejecuta con: sudo python3 capture/capture_script.py")
        return False
    except OSError as e:
        print(f"[!] Error con la interfaz {interface}: {e}")
        print(f"[!] Verifica que esté en modo monitor: iwconfig {interface}")
        return False
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        return False

if __name__ == "__main__":
    # Permitir argumentos opcionales
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberSen Packet Capture")
    parser.add_argument("--interface", "-i", default="wlan0", help="Interfaz de red")
    parser.add_argument("--duration", "-d", type=int, default=60, help="Duración en segundos")
    parser.add_argument("--output", "-o", default="data/capture.pcap", help="Archivo de salida")
    
    args = parser.parse_args()
    
    success = capture_packets(
        interface=args.interface,
        output_file=args.output,
        duration=args.duration
    )
    
    sys.exit(0 if success else 1)

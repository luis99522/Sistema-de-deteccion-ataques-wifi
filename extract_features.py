#!/usr/bin/env python3
"""
CyberSen Detector - Extractor de características MEJORADO
Etiquetado CONSERVADOR para evitar falsos positivos
Soporta múltiples capturas de tráfico normal (trafico_normal_1.pcap, trafico_normal_2.pcap, etc.)
"""
from scapy.all import *
import pandas as pd
import os
import glob
import re
from collections import defaultdict
import warnings
warnings.filterwarnings('ignore')

def detect_attack_type_from_filename(filename):
    """
    Detecta el tipo de ataque basándose en el nombre del archivo
    
    Soporta:
    - trafico_normal.pcap o trafico_normal_1.pcap hasta trafico_normal_10.pcap
    - trafico_deauth.pcap
    - trafico_beacon_flood.pcap
    - trafico_rogue_ap.pcap
    
    Args:
        filename: Nombre del archivo (ej: trafico_normal_3.pcap)
    
    Returns:
        str: Tipo detectado ('normal', 'deauth', 'beacon_flood', 'rogue_ap') o None
    """
    filename_lower = filename.lower()
    
    # Detectar trafico_normal (con o sin número)
    # trafico_normal.pcap o trafico_normal_1.pcap hasta trafico_normal_10.pcap
    if re.match(r'trafico_normal(_\d{1,2})?\.pcap', filename_lower):
        return 'normal'
    
    # Detectar otros tipos de ataques
    if 'trafico_deauth' in filename_lower:
        return 'deauth'
    elif 'trafico_beacon_flood' in filename_lower or 'trafico_beacon' in filename_lower:
        return 'beacon_flood'
    elif 'trafico_rogue_ap' in filename_lower or 'trafico_rogue' in filename_lower:
        return 'rogue_ap'
    
    return None

def detect_label_conservative(pkt, stats, filename=""):
    """
    Etiqueta paquetes de manera CONSERVADORA
    Solo marca como ataque si hay evidencia MUY CLARA
    
    Args:
        pkt: Paquete Scapy
        stats: Diccionario con estadísticas de red
        filename: Nombre del archivo para detectar etiquetas manuales
    
    Returns:
        str: Etiqueta del paquete
    """
    if not pkt.haslayer(Dot11):
        return "normal"
    
    subtype = pkt[Dot11].subtype
    src_mac = pkt.addr2 if pkt.addr2 else "00:00:00:00:00:00"
    
    # ═══════════════════════════════════════════════════════════
    # PRIORIDAD 1: Etiquetado manual basado en el nombre del archivo
    # ═══════════════════════════════════════════════════════════
    
    attack_type = detect_attack_type_from_filename(filename)
    
    if attack_type:
        # Si el archivo indica un tipo específico, etiquetar según el subtype
        if attack_type == 'normal':
            return 'normal'
        elif attack_type == 'deauth' and subtype == 12:
            return 'deauth'
        elif attack_type == 'beacon_flood' and subtype == 8:
            return 'beacon_flood'
        elif attack_type == 'rogue_ap':
            # Rogue AP puede ser beacon (8) o probe response (5)
            if subtype in [8, 5]:
                return 'rogue_ap'
            return 'normal'
    
    # ═══════════════════════════════════════════════════════════
    # PRIORIDAD 2: Etiquetado automático MUY CONSERVADOR
    # Solo si NO hay nombre descriptivo en el archivo
    # ═══════════════════════════════════════════════════════════
    
    # Inicializar estadísticas
    if src_mac not in stats['mac_counts']:
        stats['mac_counts'][src_mac] = {
            'deauth': 0, 
            'beacon': 0, 
            'total': 0,
            'first_seen': pkt.time
        }
    
    stats['mac_counts'][src_mac]['total'] += 1
    current_time = pkt.time
    time_window = current_time - stats['mac_counts'][src_mac]['first_seen']
    
    # Deauth Attack: THRESHOLD MUY ALTO
    if subtype == 12:  # Deauthentication
        stats['mac_counts'][src_mac]['deauth'] += 1
        
        # Solo etiquetar como ataque si hay MUCHÍSIMOS deauth en poco tiempo
        if time_window > 0:
            deauth_rate = stats['mac_counts'][src_mac]['deauth'] / time_window
            
            # Requiere más de 10 deauth POR SEGUNDO (muy agresivo)
            if deauth_rate > 10 and stats['mac_counts'][src_mac]['deauth'] > 50:
                return "deauth"
        
        return "normal"
    
    # Beacon Flood: THRESHOLD MUY ALTO
    elif subtype == 8:  # Beacon
        stats['mac_counts'][src_mac]['beacon'] += 1
        
        if time_window > 0:
            beacon_rate = stats['mac_counts'][src_mac]['beacon'] / time_window
            
            # Requiere más de 100 beacons POR SEGUNDO (anormal)
            if beacon_rate > 100 and stats['mac_counts'][src_mac]['beacon'] > 500:
                return "beacon_flood"
        
        return "normal"
    
    # Todo lo demás es NORMAL
    return "normal"

def extract_features_from_single_pcap(pcap_file):
    """
    Extrae características de un único archivo PCAP
    
    Args:
        pcap_file: Archivo .pcap a procesar
    
    Returns:
        DataFrame con las características extraídas
    """
    print(f"[*] Procesando: {pcap_file}")
    
    # Extraer nombre del archivo para detección de etiquetas
    base_filename = os.path.basename(pcap_file)
    
    # Detectar tipo de ataque del nombre del archivo
    attack_type = detect_attack_type_from_filename(base_filename)
    if attack_type:
        print(f"[*] Tipo detectado del nombre: {attack_type}")
    
    if not os.path.exists(pcap_file):
        print(f"[!] Error: No se encontró {pcap_file}")
        return None
    
    try:
        packets = rdpcap(pcap_file)
        print(f"[*] Total de paquetes: {len(packets)}")
    except Exception as e:
        print(f"[!] Error leyendo pcap: {e}")
        return None
    
    rows = []
    stats = {
        'mac_counts': defaultdict(dict),
        'time_window': defaultdict(list)
    }
    
    dot11_count = 0
    
    for pkt in packets:
        if pkt.haslayer(Dot11):
            dot11_count += 1
            try:
                # Extraer características básicas
                subtype = pkt[Dot11].subtype
                rssi = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -70
                src_mac = pkt.addr2 if pkt.addr2 else "00:00:00:00:00:00"
                dst_mac = pkt.addr3 if pkt.addr3 else "00:00:00:00:00:00"
                
                # Características adicionales
                frame_control = pkt[Dot11].FCfield
                retry = 1 if frame_control & 0x08 else 0
                power_mgmt = 1 if frame_control & 0x10 else 0
                
                # Frecuencia (2.4 GHz por defecto)
                freq = 2412
                
                # Timestamp
                pkt_time = float(pkt.time)
                
                # Detectar etiqueta (CONSERVADOR)
                label = detect_label_conservative(pkt, stats, base_filename)
                
                rows.append({
                    "frame_type": subtype,
                    "rssi": rssi,
                    "packet_rate": 1,  # Se calculará después
                    "time": pkt_time,
                    "src_mac": src_mac,
                    "dst_mac": dst_mac,
                    "freq": freq,
                    "retry": retry,
                    "power_mgmt": power_mgmt,
                    "label": label
                })
                
            except Exception as e:
                continue
    
    print(f"[*] Paquetes 802.11 procesados: {dot11_count}")
    
    if len(rows) == 0:
        print("[!] No se extrajeron características de este archivo.")
        return None
    
    # Crear DataFrame
    df = pd.DataFrame(rows)
    
    # Convertir tiempo a datetime
    df["time"] = pd.to_datetime(df["time"], unit="s")
    
    # Ordenar por tiempo
    df.sort_values("time", inplace=True)
    
    # Calcular packet_rate de manera robusta
    print(f"[*] Calculando packet_rate...")
    
    df_temp = df.reset_index(drop=True).copy()
    
    packet_rates = []
    for src_mac in df_temp['src_mac'].unique():
        mask = df_temp['src_mac'] == src_mac
        mac_df = df_temp[mask].copy()
        
        mac_df.set_index('time', inplace=True)
        
        rate = mac_df['frame_type'].rolling('1s', min_periods=1).count()
        
        for idx, val in rate.items():
            packet_rates.append({
                'time': idx,
                'src_mac': src_mac,
                'rate': int(val)
            })
    
    rate_df = pd.DataFrame(packet_rates)
    
    df = df.merge(
        rate_df,
        on=['time', 'src_mac'],
        how='left'
    )
    
    df['packet_rate'] = df['rate'].fillna(1).astype(int)
    df.drop(columns=['rate'], inplace=True, errors='ignore')
    
    return df

def extract_features_from_all_pcaps(input_folder="data/", output_folder="data/"):
    """
    Procesa TODOS los archivos .pcap en la carpeta
    """
    os.makedirs(input_folder, exist_ok=True)
    os.makedirs(output_folder, exist_ok=True)
    
    pcap_files = glob.glob(os.path.join(input_folder, "*.pcap"))
    
    if not pcap_files:
        print(f"[!] No se encontraron archivos .pcap en {input_folder}")
        return False
    
    # Ordenar archivos para mejor visualización
    pcap_files.sort()
    
    print(f"\n{'='*60}")
    print(f"[+] Se encontraron {len(pcap_files)} archivo(s) .pcap:")
    print(f"{'='*60}")
    for f in pcap_files:
        filename = os.path.basename(f)
        attack_type = detect_attack_type_from_filename(filename)
        if attack_type:
            print(f"   - {filename} → {attack_type}")
        else:
            print(f"   - {filename} → detección automática")
    print(f"{'='*60}\n")
    
    processed_count = 0
    total_rows = 0
    
    for pcap_file in pcap_files:
        print(f"\n{'─'*60}")
        
        df = extract_features_from_single_pcap(pcap_file)
        
        if df is None or len(df) == 0:
            print(f"[⚠️] Saltando {pcap_file} (sin datos válidos)")
            continue
        
        base_name = os.path.splitext(os.path.basename(pcap_file))[0]
        output_file = os.path.join(output_folder, f"{base_name}_dataset.csv")
        
        df.to_csv(output_file, index=False)
        
        print(f"\n[✓] Features extraídas: {len(df)} filas")
        print(f"[✓] Guardado en: {output_file}")
        print(f"\n[*] Distribución de etiquetas:")
        label_counts = df["label"].value_counts()
        for label, count in label_counts.items():
            pct = (count / len(df)) * 100
            print(f"   {label}: {count} ({pct:.2f}%)")
        
        processed_count += 1
        total_rows += len(df)
    
    print(f"\n{'='*60}")
    print(f"[✓] RESUMEN FINAL")
    print(f"{'='*60}")
    print(f"[✓] Archivos procesados: {processed_count}/{len(pcap_files)}")
    print(f"[✓] Total de registros extraídos: {total_rows}")
    print(f"[✓] Datasets guardados en: {output_folder}")
    print(f"\n[*] IMPORTANTE: Nombres de archivo soportados:")
    print(f"    ✅ trafico_normal.pcap (o trafico_normal_1.pcap hasta trafico_normal_10.pcap)")
    print(f"    ✅ trafico_deauth.pcap")
    print(f"    ✅ trafico_beacon_flood.pcap")
    print(f"    ✅ trafico_rogue_ap.pcap")
    print(f"\n[*] Siguiente paso: python3 features/build_dataset.py")
    print(f"{'='*60}\n")
    
    return processed_count > 0

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberSen Feature Extraction (Conservative)")
    parser.add_argument("--input-folder", "-i", default="data/", help="Carpeta con archivos PCAP")
    parser.add_argument("--output-folder", "-o", default="data/", help="Carpeta para guardar CSVs")
    parser.add_argument("--single-file", "-f", help="Procesar un solo archivo PCAP específico")
    
    args = parser.parse_args()
    
    if args.single_file:
        df = extract_features_from_single_pcap(args.single_file)
        if df is not None:
            base_name = os.path.splitext(os.path.basename(args.single_file))[0]
            output_file = os.path.join(args.output_folder, f"{base_name}_dataset.csv")
            df.to_csv(output_file, index=False)
            print(f"\n[✓] Dataset guardado: {output_file}")
            success = True
        else:
            success = False
    else:
        success = extract_features_from_all_pcaps(args.input_folder, args.output_folder)
    
    import sys
    sys.exit(0 if success else 1)

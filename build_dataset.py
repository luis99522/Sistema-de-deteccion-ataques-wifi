#!/usr/bin/env python3
"""
CyberSen Detector - Constructor de dataset
Consolida TODOS los *_dataset.csv generados por extract_features.py
"""
import pandas as pd
import glob
import os
from sklearn.utils import shuffle
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

def balance_dataset(df, strategy='undersample', max_ratio=5):
    """
    Balancea el dataset para evitar bias hacia clases mayoritarias
    
    Args:
        df: DataFrame con features y labels
        strategy: 'undersample' o 'oversample'
        max_ratio: Ratio máximo entre clase mayoritaria y minoritaria
    
    Returns:
        DataFrame balanceado
    """
    label_counts = df['label'].value_counts()
    print(f"\n[*] Distribución original:")
    for label, count in label_counts.items():
        pct = (count / len(df)) * 100
        print(f"   {label}: {count} ({pct:.2f}%)")
    
    # Si hay muy pocos ataques, advertir
    attack_types = [label for label in label_counts.index if label != 'normal']
    if len(attack_types) == 0:
        print(f"\n[⚠️] ADVERTENCIA: No se detectaron ataques en el dataset")
        print(f"[⚠️] El modelo solo aprenderá tráfico 'normal'")
        print(f"[⚠️] Considera capturar tráfico con ataques simulados:")
        print(f"    • Deauth: aireplay-ng -0 0 -a [BSSID] wlan0")
        print(f"    • Beacon flood: mdk4 wlan0 b -f [AP_LIST]")
        print(f"    • Auth flood: mdk4 wlan0 a -a [BSSID]")
        return df
    
    if strategy == 'undersample':
        # Submuestreo de la clase mayoritaria
        minority_size = label_counts.min()
        target_size = min(minority_size * max_ratio, label_counts.max())
        
        balanced_dfs = []
        for label in df['label'].unique():
            label_df = df[df['label'] == label]
            if len(label_df) > target_size:
                label_df = label_df.sample(n=int(target_size), random_state=42)
            balanced_dfs.append(label_df)
        
        df_balanced = pd.concat(balanced_dfs, ignore_index=True)
        df_balanced = shuffle(df_balanced, random_state=42)
        
        print(f"\n[*] Distribución balanceada (undersample):")
        label_counts_balanced = df_balanced['label'].value_counts()
        for label, count in label_counts_balanced.items():
            pct = (count / len(df_balanced)) * 100
            print(f"   {label}: {count} ({pct:.2f}%)")
        
        return df_balanced
    
    else:
        # Por ahora solo implementamos undersample
        return df

def build_dataset(input_folder="data/", output_file="data/final_dataset.csv", balance=True):
    """
    Construye dataset final consolidando múltiples capturas
    
    Args:
        input_folder: Carpeta con archivos CSV
        output_file: Archivo de salida
        balance: Si se debe balancear el dataset
    """
    os.makedirs(input_folder, exist_ok=True)
    
    # Buscar todos los CSV generados por extract_features.py
    # Patrón: *_dataset.csv (ej: trafico_normal_dataset.csv)
    csv_files = glob.glob(os.path.join(input_folder, "*_dataset.csv"))
    
    if not csv_files:
        print(f"[!] No se encontraron archivos *_dataset.csv en {input_folder}")
        print(f"[!] Asegúrate de ejecutar extract_features.py primero")
        print(f"\n[*] Buscando archivos CSV alternativos...")
        
        # Buscar cualquier CSV como fallback
        csv_files = glob.glob(os.path.join(input_folder, "*.csv"))
        csv_files = [f for f in csv_files if 'final_dataset' not in f]
        
        if not csv_files:
            print(f"[!] No se encontraron archivos CSV en {input_folder}")
            return False
    
    print(f"\n{'='*60}")
    print(f"[+] Archivos CSV encontrados: {len(csv_files)}")
    print(f"{'='*60}")
    for f in csv_files:
        size_kb = os.path.getsize(f) / 1024
        print(f"   - {os.path.basename(f)} ({size_kb:.2f} KB)")
    print(f"{'='*60}\n")
    
    # Cargar y concatenar todos los CSV
    dfs = []
    total_rows_loaded = 0
    
    for f in csv_files:
        try:
            print(f"[*] Cargando: {os.path.basename(f)}")
            df_temp = pd.read_csv(f)
            
            # Verificar columnas necesarias
            required_cols = ['frame_type', 'rssi', 'packet_rate', 'freq', 'label']
            missing_cols = [col for col in required_cols if col not in df_temp.columns]
            
            if missing_cols:
                print(f"[⚠️] Ignorando {os.path.basename(f)}: faltan columnas {missing_cols}")
                continue
            
            print(f"    Registros: {len(df_temp)}")
            
            # Mostrar distribución
            label_counts = df_temp['label'].value_counts()
            for label, count in label_counts.items():
                print(f"      {label}: {count}")
            
            dfs.append(df_temp)
            total_rows_loaded += len(df_temp)
            
        except Exception as e:
            print(f"[⚠️] Error leyendo {os.path.basename(f)}: {e}")
            continue
    
    if not dfs:
        print(f"[!] No se pudieron cargar datasets válidos")
        return False
    
    print(f"\n[*] Consolidando {len(dfs)} dataset(s)...")
    df = pd.concat(dfs, ignore_index=True)
    
    print(f"[*] Total de registros cargados: {total_rows_loaded}")
    
    # Eliminar duplicados
    original_len = len(df)
    df.drop_duplicates(inplace=True)
    removed = original_len - len(df)
    
    if removed > 0:
        print(f"[*] Duplicados eliminados: {removed}")
    
    print(f"[*] Registros finales antes del balanceo: {len(df)}")
    
    # Mostrar distribución antes del balanceo
    print(f"\n{'='*60}")
    print(f"📊 DISTRIBUCIÓN DE ETIQUETAS (ANTES DEL BALANCEO)")
    print(f"{'='*60}")
    label_counts = df['label'].value_counts()
    total = len(df)
    
    for label, count in label_counts.items():
        pct = (count / total) * 100
        bar_length = int(pct / 2)  # Barra visual
        bar = '█' * bar_length
        print(f"{label:15s} | {bar} {count:6d} ({pct:5.2f}%)")
    print(f"{'='*60}")
    
    # Balancear dataset si es necesario
    if balance and len(df['label'].unique()) > 1:
        print(f"\n[*] Aplicando balanceo de clases...")
        df = balance_dataset(df, strategy='undersample', max_ratio=10)
    
    # Mezclar aleatoriamente
    df = shuffle(df, random_state=42)
    
    # Guardar dataset combinado
    df.to_csv(output_file, index=False)
    
    print(f"\n{'='*60}")
    print(f"[✓] DATASET FINAL CREADO")
    print(f"{'='*60}")
    print(f"[✓] Archivo: {output_file}")
    print(f"[✓] Total de registros: {len(df)}")
    print(f"[✓] Columnas: {list(df.columns)}")
    
    # Verificaciones finales
    unique_labels = df['label'].unique()
    print(f"[✓] Clases detectadas: {', '.join(unique_labels)}")
    
    if len(unique_labels) < 2:
        print(f"\n{'='*60}")
        print(f"[⚠️] ADVERTENCIA: SOLO HAY UNA CLASE EN EL DATASET")
        print(f"{'='*60}")
        print(f"[⚠️] El modelo NO podrá aprender a distinguir ataques")
        print(f"\n[*] SOLUCIÓN:")
        print(f"    1. Simula ataques WiFi con herramientas:")
        print(f"       • Deauth: aireplay-ng -0 10 -a [BSSID] wlan0")
        print(f"       • Beacon: mdk4 wlan0 b -f ap_list.txt")
        print(f"       • Auth: mdk4 wlan0 a -a [BSSID]")
        print(f"    2. Captura ese tráfico: python3 capture/capture_script.py")
        print(f"    3. Guárdalo con nombre descriptivo (ej: trafico_deauth.pcap)")
        print(f"    4. Re-ejecuta: python3 features/extract_features.py")
        print(f"    5. Re-ejecuta: python3 features/build_dataset.py")
        print(f"{'='*60}\n")
    else:
        print(f"\n[✓] Dataset listo para entrenar el modelo")
        print(f"[*] Siguiente paso: python3 model/train_model.py\n")
    
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberSen Dataset Builder")
    parser.add_argument("--input", "-i", default="data/", help="Carpeta con CSVs")
    parser.add_argument("--output", "-o", default="data/final_dataset.csv", help="Archivo de salida")
    parser.add_argument("--no-balance", action="store_true", help="No balancear dataset")
    
    args = parser.parse_args()
    
    success = build_dataset(
        input_folder=args.input,
        output_file=args.output,
        balance=not args.no_balance
    )
    
    import sys
    sys.exit(0 if success else 1)

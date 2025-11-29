#!/usr/bin/env python3
"""
CyberSen Detector - Entrenamiento del modelo
Optimizado con validación cruzada y métricas detalladas
"""
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import LabelEncoder
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

def train_model(dataset_file="data/final_dataset.csv", model_output="model/model.pkl"):
    """
    Entrena un modelo Random Forest para detectar ataques WiFi
    
    Args:
        dataset_file: Archivo CSV con el dataset
        model_output: Ruta donde guardar el modelo
    """
    print(f"[*] Cargando dataset: {dataset_file}")
    
    if not os.path.exists(dataset_file):
        print(f"[!] Error: No se encontró {dataset_file}")
        print(f"[!] Ejecuta build_dataset.py primero")
        return False
    
    try:
        df = pd.read_csv(dataset_file)
    except Exception as e:
        print(f"[!] Error leyendo dataset: {e}")
        return False
    
    print(f"[*] Total de registros: {len(df)}")
    print(f"[*] Columnas: {list(df.columns)}")
    
    # Seleccionar features
    feature_cols = ["frame_type", "rssi", "packet_rate", "freq"]
    
    # Verificar que existan las columnas
    missing_cols = [col for col in feature_cols + ["label"] if col not in df.columns]
    if missing_cols:
        print(f"[!] Error: Faltan columnas: {missing_cols}")
        return False
    
    # Añadir features adicionales si existen
    optional_features = ["retry", "power_mgmt"]
    for feat in optional_features:
        if feat in df.columns:
            feature_cols.append(feat)
    
    X = df[feature_cols]
    y = df["label"]
    
    print(f"\n[*] Features utilizadas: {feature_cols}")
    print(f"[*] Distribución de clases:")
    print(y.value_counts())
    
    # Verificar si hay suficientes datos
    if len(df) < 100:
        print(f"\n[⚠️] ADVERTENCIA: Dataset muy pequeño ({len(df)} muestras)")
        print(f"[⚠️] Se recomienda al menos 1000 muestras para buen rendimiento")
    
    # Verificar si hay clases para aprender
    unique_labels = y.unique()
    if len(unique_labels) < 2:
        print(f"\n[⚠️] ADVERTENCIA: Solo hay una clase ({unique_labels[0]})")
        print(f"[⚠️] El modelo no podrá detectar ataques")
        print(f"[⚠️] Captura tráfico con ataques simulados")
    
    # Split dataset
    test_size = 0.2
    if len(df) < 50:
        test_size = 0.3  # Usar más datos de prueba si hay pocos
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, 
        test_size=test_size, 
        random_state=42,
        stratify=y if len(unique_labels) > 1 else None
    )
    
    print(f"\n[*] Set de entrenamiento: {len(X_train)} muestras")
    print(f"[*] Set de prueba: {len(X_test)} muestras")
    
    # Entrenar modelo con parámetros optimizados
    print(f"\n[*] Entrenando Random Forest...")
    
    model = RandomForestClassifier(
        n_estimators=150,           # Más árboles para mejor generalización
        max_depth=15,                # Limitar profundidad para evitar overfitting
        min_samples_split=5,         # Mínimo de muestras para dividir
        min_samples_leaf=2,          # Mínimo de muestras en hojas
        class_weight='balanced',     # Balancear clases automáticamente
        random_state=42,
        n_jobs=-1                    # Usar todos los cores
    )
    
    model.fit(X_train, y_train)
    
    print(f"[✓] Modelo entrenado")
    
    # Validación cruzada (solo si hay suficientes datos)
    if len(df) >= 100 and len(unique_labels) > 1:
        print(f"\n[*] Validación cruzada (5-fold)...")
        cv_scores = cross_val_score(model, X, y, cv=5)
        print(f"[*] Accuracy promedio: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    
    # Evaluación en test set
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n{'='*60}")
    print(f"[✓] RESULTADOS DEL MODELO")
    print(f"{'='*60}")
    print(f"\n[*] Accuracy en test: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    # Reporte de clasificación
    print(f"\n[*] Reporte de clasificación:\n")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # Matriz de confusión
    print(f"[*] Matriz de confusión:")
    cm = confusion_matrix(y_test, y_pred, labels=model.classes_)
    print(f"\nClases: {list(model.classes_)}")
    print(cm)
    
    # Importancia de features
    print(f"\n[*] Importancia de características:")
    for feat, imp in zip(feature_cols, model.feature_importances_):
        print(f"   {feat}: {imp:.4f}")
    
    # Advertencias sobre el rendimiento
    if accuracy < 0.7:
        print(f"\n[⚠️] ADVERTENCIA: Accuracy baja ({accuracy:.2f})")
        print(f"[⚠️] Posibles causas:")
        print(f"    - Dataset desbalanceado")
        print(f"    - Pocas muestras de ataques")
        print(f"    - Features insuficientes")
        print(f"[⚠️] Recomendación: Captura más tráfico variado")
    
    # Guardar modelo
    os.makedirs(os.path.dirname(model_output), exist_ok=True)
    joblib.dump(model, model_output)
    
    # Guardar también las columnas de features
    joblib.dump(feature_cols, model_output.replace('.pkl', '_features.pkl'))
    
    print(f"\n[✓] Modelo guardado en: {model_output}")
    print(f"[✓] Features guardadas en: {model_output.replace('.pkl', '_features.pkl')}")
    
    return True

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="CyberSen Model Training")
    parser.add_argument("--dataset", "-d", default="data/final_dataset.csv", help="Dataset CSV")
    parser.add_argument("--output", "-o", default="model/model.pkl", help="Modelo de salida")
    
    args = parser.parse_args()
    
    success = train_model(
        dataset_file=args.dataset,
        model_output=args.output
    )
    
    import sys
    sys.exit(0 if success else 1)

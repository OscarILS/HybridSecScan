"""
Script para procesar archivos JSON de NVD y convertirlos a CSV para entrenamiento de ML

Autor: Oscar Isaac Laguna Santa Cruz
Universidad Nacional Mayor de San Marcos
Fecha: Noviembre 2025

Requisitos:
    pip install pandas tqdm

Uso:
    python scripts/process_nvd_datasets.py
"""

import json
import pandas as pd
from pathlib import Path
from typing import List, Dict
from collections import Counter
import random

try:
    from tqdm import tqdm
except ImportError:
    print("⚠️ Advertencia: tqdm no instalado. Instala con: pip install tqdm")
    tqdm = lambda x, **kwargs: x


class NVDProcessor:
    """Procesador de datos NVD para entrenamiento de ML"""
    
    def __init__(self, input_dir: Path, output_dir: Path):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Mapeo de severidad CVSS a categorías
        self.severity_mapping = {
            "CRITICAL": "HIGH",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "NONE": "INFO"
        }
        
    def extract_cve_data(self, cve_item: Dict) -> Dict:
        """
        Extrae información relevante de un CVE item
        
        Args:
            cve_item: Diccionario con datos de CVE en formato NVD API 2.0
        
        Returns:
            Diccionario con datos procesados
        """
        try:
            cve = cve_item.get("cve", {})
            
            # ID del CVE
            cve_id = cve.get("id", "UNKNOWN")
            
            # Descripción
            descriptions = cve.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # CWE (weakness types)
            cwe_list = []
            weaknesses = cve.get("weaknesses", [])
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    cwe_value = desc.get("value", "")
                    if cwe_value.startswith("CWE-"):
                        cwe_list.append(cwe_value)
            
            cwe = cwe_list[0] if cwe_list else "CWE-Other"
            
            # Severidad CVSS
            metrics = cve_item.get("metrics", {})
            severity = "UNKNOWN"
            cvss_score = 0.0
            
            # Intentar obtener CVSS v3.1, v3.0, o v2.0
            for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]
                    cvss_data = metric.get("cvssData", {})
                    severity = cvss_data.get("baseSeverity", metric.get("baseSeverity", "UNKNOWN"))
                    cvss_score = cvss_data.get("baseScore", metric.get("cvssData", {}).get("baseScore", 0.0))
                    break
            
            # Normalizar severidad
            severity = self.severity_mapping.get(severity, "MEDIUM")
            
            # Fecha de publicación
            published = cve.get("published", "")
            
            # Referencias
            references = cve.get("references", [])
            ref_urls = [ref.get("url", "") for ref in references[:3]]  # Solo primeras 3
            
            return {
                "cve_id": cve_id,
                "description": description[:500],  # Limitar a 500 caracteres
                "cwe": cwe,
                "severity": severity,
                "cvss_score": cvss_score,
                "published_date": published,
                "references": "|".join(ref_urls)
            }
            
        except Exception as e:
            print(f"⚠️ Error procesando CVE: {e}")
            return None
    
    def process_json_file(self, json_file: Path) -> List[Dict]:
        """
        Procesa un archivo JSON de NVD
        
        Args:
            json_file: Ruta al archivo JSON
        
        Returns:
            Lista de CVEs procesados
        """
        print(f"\n📄 Procesando: {json_file.name}")
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            vulnerabilities = data.get("vulnerabilities", [])
            print(f"   Total de CVEs en archivo: {len(vulnerabilities)}")
            
            processed_cves = []
            for vuln in tqdm(vulnerabilities, desc=f"   Extrayendo {json_file.stem}"):
                cve_data = self.extract_cve_data(vuln)
                if cve_data:
                    processed_cves.append(cve_data)
            
            print(f"   ✅ CVEs procesados: {len(processed_cves)}")
            return processed_cves
            
        except Exception as e:
            print(f"   ❌ Error leyendo archivo: {e}")
            return []
    
    def generate_correlation_dataset(self, cves: List[Dict]) -> pd.DataFrame:
        """
        Genera dataset de correlación SAST-DAST a partir de CVEs
        
        Esta función simula hallazgos SAST y DAST basados en los CVEs de NVD.
        Para un dataset real, necesitarías ejecutar herramientas reales sobre código vulnerable.
        
        Args:
            cves: Lista de CVEs procesados
        
        Returns:
            DataFrame con formato SAST-DAST
        """
        print("\n🔄 Generando dataset de correlación SAST-DAST...")
        
        rows = []
        
        # Herramientas de análisis
        sast_tools = ["bandit", "semgrep", "sonarqube"]
        dast_tools = ["zap", "burp", "acunetix"]
        
        for idx, cve in enumerate(tqdm(cves, desc="Generando correlaciones")):
            # Determinar si SAST y DAST encontrarían esta vulnerabilidad
            # Basado en el tipo de CWE
            cwe = cve["cwe"]
            
            # CWEs típicamente detectables por SAST
            sast_detectable = cwe in [
                "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-94", 
                "CWE-611", "CWE-798", "CWE-259", "CWE-327", "CWE-502"
            ]
            
            # CWEs típicamente detectables por DAST
            dast_detectable = cwe in [
                "CWE-89", "CWE-79", "CWE-78", "CWE-352", "CWE-434",
                "CWE-601", "CWE-918", "CWE-319", "CWE-287", "CWE-284"
            ]
            
            # Generar registro solo si al menos una herramienta lo detecta
            if sast_detectable or dast_detectable:
                # Mapeo de CWE a tipo de vulnerabilidad
                vuln_type_map = {
                    "CWE-89": "SQL_INJECTION",
                    "CWE-79": "XSS",
                    "CWE-78": "COMMAND_INJECTION",
                    "CWE-22": "PATH_TRAVERSAL",
                    "CWE-94": "CODE_INJECTION",
                    "CWE-352": "CSRF",
                    "CWE-434": "FILE_UPLOAD",
                    "CWE-798": "HARDCODED_CREDENTIALS",
                    "CWE-327": "WEAK_CRYPTO",
                    "CWE-502": "DESERIALIZATION"
                }
                
                vuln_type = vuln_type_map.get(cwe, "SECURITY_MISC")
                
                # Simular hallazgo SAST
                sast_id = f"SAST-{idx:05d}" if sast_detectable else None
                sast_file = f"src/api/controller_{random.randint(1,100)}.py" if sast_detectable else None
                sast_line = random.randint(10, 500) if sast_detectable else None
                sast_tool = random.choice(sast_tools) if sast_detectable else None
                
                # Simular hallazgo DAST
                dast_id = f"DAST-{idx:05d}" if dast_detectable else None
                dast_endpoint = f"/api/v1/resource_{random.randint(1,50)}" if dast_detectable else None
                dast_tool = random.choice(dast_tools) if dast_detectable else None
                
                # Determinar si están correlacionados
                # Correlacionados si ambos detectan Y son del mismo CWE
                is_correlated = 1 if (sast_detectable and dast_detectable) else 0
                confidence = round(random.uniform(0.75, 0.98), 2) if is_correlated else round(random.uniform(0.20, 0.65), 2)
                
                row = {
                    "sast_id": sast_id or "",
                    "sast_type": vuln_type if sast_detectable else "",
                    "sast_severity": cve["severity"] if sast_detectable else "",
                    "sast_file": sast_file or "",
                    "sast_line": sast_line or "",
                    "sast_description": cve["description"][:200] if sast_detectable else "",
                    "sast_cwe": cwe if sast_detectable else "",
                    "sast_tool": sast_tool or "",
                    "dast_id": dast_id or "",
                    "dast_type": vuln_type if dast_detectable else "",
                    "dast_severity": cve["severity"] if dast_detectable else "",
                    "dast_endpoint": dast_endpoint or "",
                    "dast_description": cve["description"][:200] if dast_detectable else "",
                    "dast_cwe": cwe if dast_detectable else "",
                    "dast_tool": dast_tool or "",
                    "is_correlated": is_correlated,
                    "confidence": confidence,
                    "cve_reference": cve["cve_id"]
                }
                
                rows.append(row)
        
        df = pd.DataFrame(rows)
        print(f"✅ Dataset generado: {len(df)} registros")
        return df
    
    def split_dataset(self, df: pd.DataFrame, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1):
        """
        Divide el dataset en entrenamiento, validación y prueba
        
        Args:
            df: DataFrame completo
            train_ratio: Proporción para entrenamiento
            val_ratio: Proporción para validación
            test_ratio: Proporción para prueba
        
        Returns:
            Tupla (train_df, val_df, test_df)
        """
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 0.01, "Las proporciones deben sumar 1.0"
        
        # Shuffle
        df_shuffled = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        n = len(df_shuffled)
        train_end = int(n * train_ratio)
        val_end = train_end + int(n * val_ratio)
        
        train_df = df_shuffled[:train_end]
        val_df = df_shuffled[train_end:val_end]
        test_df = df_shuffled[val_end:]
        
        return train_df, val_df, test_df
    
    def process_all(self):
        """Procesa todos los archivos JSON de NVD"""
        print("=" * 70)
        print("  NVD Dataset Processor - HybridSecScan")
        print("  Universidad Nacional Mayor de San Marcos")
        print("=" * 70)
        
        # Encontrar todos los archivos JSON
        json_files = sorted(self.input_dir.glob("nvdcve-*.json"))
        
        if not json_files:
            print("❌ No se encontraron archivos JSON en data/raw/nvd/")
            return
        
        print(f"\n📁 Archivos encontrados: {len(json_files)}")
        for f in json_files:
            print(f"   - {f.name}")
        
        # Procesar cada archivo
        all_cves = []
        for json_file in json_files:
            cves = self.process_json_file(json_file)
            all_cves.extend(cves)
        
        print(f"\n📊 Total de CVEs procesados: {len(all_cves)}")
        
        if not all_cves:
            print("❌ No se pudieron procesar CVEs")
            return
        
        # Estadísticas
        cwe_counter = Counter([cve["cwe"] for cve in all_cves])
        severity_counter = Counter([cve["severity"] for cve in all_cves])
        
        print("\n📈 Estadísticas:")
        print(f"   Top 10 CWEs:")
        for cwe, count in cwe_counter.most_common(10):
            print(f"      {cwe}: {count}")
        
        print(f"\n   Severidades:")
        for severity, count in severity_counter.items():
            print(f"      {severity}: {count}")
        
        # Generar dataset de correlación
        df = self.generate_correlation_dataset(all_cves)
        
        # Split dataset
        train_df, val_df, test_df = self.split_dataset(df)
        
        print(f"\n📦 División del dataset:")
        print(f"   Training:   {len(train_df)} muestras ({len(train_df)/len(df)*100:.1f}%)")
        print(f"   Validation: {len(val_df)} muestras ({len(val_df)/len(df)*100:.1f}%)")
        print(f"   Test:       {len(test_df)} muestras ({len(test_df)/len(df)*100:.1f}%)")
        
        # Guardar CSVs
        train_file = self.output_dir / "training_set.csv"
        val_file = self.output_dir / "validation_set.csv"
        test_file = self.output_dir / "test_set.csv"
        
        train_df.to_csv(train_file, index=False)
        val_df.to_csv(val_file, index=False)
        test_df.to_csv(test_file, index=False)
        
        print(f"\n💾 Archivos guardados:")
        print(f"   ✅ {train_file}")
        print(f"   ✅ {val_file}")
        print(f"   ✅ {test_file}")
        
        # Estadísticas de correlación
        print(f"\n🔗 Estadísticas de correlación:")
        print(f"   Correlaciones positivas: {df['is_correlated'].sum()} ({df['is_correlated'].sum()/len(df)*100:.1f}%)")
        print(f"   Correlaciones negativas: {len(df) - df['is_correlated'].sum()} ({(len(df) - df['is_correlated'].sum())/len(df)*100:.1f}%)")
        print(f"   Confianza promedio (correlacionadas): {df[df['is_correlated']==1]['confidence'].mean():.2f}")
        print(f"   Confianza promedio (no correlacionadas): {df[df['is_correlated']==0]['confidence'].mean():.2f}")
        
        print("\n✅ ¡Procesamiento completado!")
        print("\n📝 Próximos pasos:")
        print("   1. Revisar los archivos CSV generados en data/processed/")
        print("   2. Entrenar el modelo de ML: python backend/correlation_engine.py")
        print("   3. Evaluar métricas: precision, recall, F1-score")


def main():
    """Función principal"""
    # Directorios
    input_dir = Path("data/raw/nvd")
    output_dir = Path("data/processed")
    
    # Crear procesador
    processor = NVDProcessor(input_dir, output_dir)
    
    # Procesar todos los archivos
    processor.process_all()


if __name__ == "__main__":
    main()

import io
from typing import Optional
from fastapi import FastAPI, File, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from ingest_data import CSV_FEATURE_COLS, TLS12Adapter
import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
import requests
import urllib3
import os
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = FastAPI(title="Eclipse IDS Dashboard API")

@app.get("/health")
def health():
  return {"status": "ok"}

# Izinkan akses dari Frontend (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- KONFIGURASI ---
API_URL = "https://yuellen.my.id/pred/predict"

# --- MODEL METRICS (dari evaluasi test set Hilal) ---
MODEL_ACCURACY = "99.35%"
MODEL_PRECISION = "96.65%"
MODEL_RECALL = "99.13%"
MODEL_F1 = "97.88%"
MODEL_FPR = "0.61%"
load_dotenv() 
DATABASE_URL = os.getenv("DATABASE_URL")  

session = requests.Session()
session.mount("https://", TLS12Adapter())


def get_db():
  return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


# 1. KPI Summary & Persentase Attack
@app.get("/api/dashboard/summary")
def get_summary():
  conn = get_db()
  cur = conn.cursor()
  cur.execute("""
        SELECT 
            COUNT(*) AS total_traffic,
            COUNT(*) FILTER (WHERE prediction_code = 1) AS total_attack,
            COUNT(*) FILTER (WHERE prediction_code = 0) AS total_benign,
            COALESCE(ROUND((COUNT(*) FILTER (WHERE prediction_code = 1)::NUMERIC / NULLIF(COUNT(*), 0)) * 100, 2), 0) AS attack_percentage,
            COUNT(DISTINCT dst_ip) FILTER (WHERE prediction_code = 1) AS affected_assets_count,
            COUNT(DISTINCT src_ip) FILTER (WHERE prediction_code = 1) AS unique_attackers_count
        FROM intrusion_logs;
    """)
  data = cur.fetchone()
  cur.close()
  conn.close()
  return data


# 2. Grafik Traffic per Hour (Benign vs Malicious)
@app.get("/api/dashboard/traffic-hourly")
def get_traffic_hourly():
  conn = get_db()
  cur = conn.cursor()
  cur.execute("""
        SELECT 
            TO_CHAR(DATE_TRUNC('hour', flow_timestamp), 'YYYY-MM-DD HH24:00') AS hour,
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE prediction_code = 1) AS attack_count,
            COUNT(*) FILTER (WHERE prediction_code = 0) AS benign_count
        FROM intrusion_logs
        GROUP BY DATE_TRUNC('hour', flow_timestamp)
        ORDER BY DATE_TRUNC('hour', flow_timestamp) ASC;
    """)
  rows = cur.fetchall()
  cur.close()
  conn.close()
  return {"data": rows}


# 3. Top IP Penyerang (src_ip) & Top Aset Diserang (dst_ip)
@app.get("/api/dashboard/top-ips")
def get_top_ips(limit: int = 5):
  conn = get_db()
  cur = conn.cursor()

  cur.execute(
      """
        SELECT src_ip AS ip_address, COUNT(*) AS attack_count, MAX(attack_probability) AS max_confidence
        FROM intrusion_logs
        WHERE prediction_code = 1
        GROUP BY src_ip
        ORDER BY attack_count DESC
        LIMIT %s;
    """,
      (limit,),
  )
  attackers = cur.fetchall()

  cur.execute(
      """
        SELECT dst_ip AS ip_address, COUNT(*) AS attack_count, ARRAY_AGG(DISTINCT dst_port) AS targeted_ports
        FROM intrusion_logs
        WHERE prediction_code = 1
        GROUP BY dst_ip
        ORDER BY attack_count DESC
        LIMIT %s;
    """,
      (limit,),
  )
  targets = cur.fetchall()

  cur.close()
  conn.close()
  return {"top_attackers": attackers, "targeted_assets": targets}


# 4. Tabel Riwayat Log dengan Filter & Pagination
@app.get("/api/dashboard/logs")
def get_logs(
    label: Optional[str] = Query(
        None, description="Filter: 'Malicious' atau 'Benign'"
    ),
    search_ip: Optional[str] = Query(
        None, description="Cari berdasarkan src_ip atau dst_ip"
    ),
    page: int = 1,
    limit: int = 20,
):
  offset = (page - 1) * limit
  conditions = []
  params = []

  if label:
    conditions.append("prediction_label = %s")
    params.append(label)
  if search_ip:
    conditions.append("(src_ip ILIKE %s OR dst_ip ILIKE %s)")
    params.extend([f"%{search_ip}%", f"%{search_ip}%"])

  where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

  conn = get_db()
  cur = conn.cursor()
  cur.execute(f"SELECT COUNT(*) AS total FROM intrusion_logs {where_clause};", params)
  total = cur.fetchone()["total"]

  cur.execute(
      f"""
        SELECT id, scenario_file, src_ip, dst_ip, src_port, dst_port, protocol,
               flow_timestamp, flow_duration, total_packets,
               prediction_label, attack_probability
        FROM intrusion_logs
        {where_clause}
        ORDER BY flow_timestamp DESC
        LIMIT %s OFFSET %s;
    """,
      params + [limit, offset],
  )
  rows = cur.fetchall()
  cur.close()
  conn.close()

  return {"total": total, "page": page, "limit": limit, "data": rows}

# 6. Model Metrics (panel Model Performance di frontend)
@app.get("/api/dashboard/model-metrics")
def get_model_metrics():
  conn = get_db()
  cur = conn.cursor()

  cur.execute("SELECT COUNT(*) AS c FROM intrusion_logs WHERE created_at::date = CURRENT_DATE;")
  daily_predictions = cur.fetchone()["c"]

  cur.execute("SELECT COUNT(*) AS c FROM intrusion_logs;")
  total_predictions = cur.fetchone()["c"]

  cur.close()
  conn.close()

  return {
      "accuracy": MODEL_ACCURACY,
      "precision": MODEL_PRECISION,
      "recall": MODEL_RECALL,
      "f1_score": MODEL_F1,
      "fpr": MODEL_FPR,
      "false_positive_rate": MODEL_FPR,
      "daily_predictions": daily_predictions,
      "total_predictions": total_predictions,
      "model_status": "Aktif",
  }
  
# 5. Endpoint Upload CSV Baru untuk Dianalisis Langsung
@app.post("/api/analyze-csv")
async def analyze_uploaded_csv(file: UploadFile = File(...)):
  contents = await file.read()
  df = pd.read_csv(io.BytesIO(contents))

  X = df[CSV_FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0.0)
  res = session.post(API_URL, json={"data": X.values.tolist()}, timeout=60)
  res.raise_for_status()
  pred_data = res.json()

  records = []
  for i, row in df.iterrows():
    records.append((
        file.filename,
        str(row["src_ip"]),
        str(row["dst_ip"]),
        int(row["src_port"]),
        int(row["dst_port"]),
        int(row["protocol"]),
        str(row["timestamp"]),
        float(row["flow_duration"]),
        int(row["tot_fwd_pkts"] + row["tot_bwd_pkts"]),
        int(pred_data["predictions"][i]),
        str(pred_data["labels"][i]),
        float(pred_data["probabilities"][i]),
    ))

  conn = psycopg2.connect(DATABASE_URL)
  cur = conn.cursor()
  execute_values(
      cur,
      """
        INSERT INTO intrusion_logs (
            scenario_file, src_ip, dst_ip, src_port, dst_port, protocol,
            flow_timestamp, flow_duration, total_packets,
            prediction_code, prediction_label, attack_probability
        ) VALUES %s
    """,
      records,
  )
  conn.commit()
  cur.close()
  conn.close()

  attack_count = sum(pred_data["predictions"])
  return {
      "message": "Analisis selesai dan tersimpan ke database",
      "file": file.filename,
      "total_rows": len(records),
      "detected_attacks": attack_count,
      "detected_benign": len(records) - attack_count,
  }
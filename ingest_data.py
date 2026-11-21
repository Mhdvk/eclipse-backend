import glob
import os
import ssl
from dotenv import load_dotenv  # <-- Tambahan baru
import numpy as np
import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
import requests
from requests.adapters import HTTPAdapter
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()  # <-- Tambahan baru untuk membaca file .env

# --- KONFIGURASI ---
API_URL = "https://yuellen.my.id/pred/predict"
DATABASE_URL = os.getenv("DATABASE_URL")  

# Mapping urutan 77 fitur API Hilal -> nama kolom di CSV attack_sim
FEATURE_MAPPING = [
    ("Protocol", "protocol"),
    ("Flow Duration", "flow_duration"),
    ("Total Fwd Packets", "tot_fwd_pkts"),
    ("Total Backward Packets", "tot_bwd_pkts"),
    ("Fwd Packets Length Total", "totlen_fwd_pkts"),
    ("Bwd Packets Length Total", "totlen_bwd_pkts"),
    ("Fwd Packet Length Max", "fwd_pkt_len_max"),
    ("Fwd Packet Length Min", "fwd_pkt_len_min"),
    ("Fwd Packet Length Mean", "fwd_pkt_len_mean"),
    ("Fwd Packet Length Std", "fwd_pkt_len_std"),
    ("Bwd Packet Length Max", "bwd_pkt_len_max"),
    ("Bwd Packet Length Min", "bwd_pkt_len_min"),
    ("Bwd Packet Length Mean", "bwd_pkt_len_mean"),
    ("Bwd Packet Length Std", "bwd_pkt_len_std"),
    ("Flow Bytes/s", "flow_byts_s"),
    ("Flow Packets/s", "flow_pkts_s"),
    ("Flow IAT Mean", "flow_iat_mean"),
    ("Flow IAT Std", "flow_iat_std"),
    ("Flow IAT Max", "flow_iat_max"),
    ("Flow IAT Min", "flow_iat_min"),
    ("Fwd IAT Total", "fwd_iat_tot"),
    ("Fwd IAT Mean", "fwd_iat_mean"),
    ("Fwd IAT Std", "fwd_iat_std"),
    ("Fwd IAT Max", "fwd_iat_max"),
    ("Fwd IAT Min", "fwd_iat_min"),
    ("Bwd IAT Total", "bwd_iat_tot"),
    ("Bwd IAT Mean", "bwd_iat_mean"),
    ("Bwd IAT Std", "bwd_iat_std"),
    ("Bwd IAT Max", "bwd_iat_max"),
    ("Bwd IAT Min", "bwd_iat_min"),
    ("Fwd PSH Flags", "fwd_psh_flags"),
    ("Bwd PSH Flags", "bwd_psh_flags"),
    ("Fwd URG Flags", "fwd_urg_flags"),
    ("Bwd URG Flags", "bwd_urg_flags"),
    ("Fwd Header Length", "fwd_header_len"),
    ("Bwd Header Length", "bwd_header_len"),
    ("Fwd Packets/s", "fwd_pkts_s"),
    ("Bwd Packets/s", "bwd_pkts_s"),
    ("Packet Length Min", "pkt_len_min"),
    ("Packet Length Max", "pkt_len_max"),
    ("Packet Length Mean", "pkt_len_mean"),
    ("Packet Length Std", "pkt_len_std"),
    ("Packet Length Variance", "pkt_len_var"),
    ("FIN Flag Count", "fin_flag_cnt"),
    ("SYN Flag Count", "syn_flag_cnt"),
    ("RST Flag Count", "rst_flag_cnt"),
    ("PSH Flag Count", "psh_flag_cnt"),
    ("ACK Flag Count", "ack_flag_cnt"),
    ("URG Flag Count", "urg_flag_cnt"),
    ("CWE Flag Count", "cwr_flag_count"),
    ("ECE Flag Count", "ece_flag_cnt"),
    ("Down/Up Ratio", "down_up_ratio"),
    ("Avg Packet Size", "pkt_size_avg"),
    ("Avg Fwd Segment Size", "fwd_seg_size_avg"),
    ("Avg Bwd Segment Size", "bwd_seg_size_avg"),
    ("Fwd Avg Bytes/Bulk", "fwd_byts_b_avg"),
    ("Fwd Avg Packets/Bulk", "fwd_pkts_b_avg"),
    ("Fwd Avg Bulk Rate", "fwd_blk_rate_avg"),
    ("Bwd Avg Bytes/Bulk", "bwd_byts_b_avg"),
    ("Bwd Avg Packets/Bulk", "bwd_pkts_b_avg"),
    ("Bwd Avg Bulk Rate", "bwd_blk_rate_avg"),
    ("Subflow Fwd Packets", "subflow_fwd_pkts"),
    ("Subflow Fwd Bytes", "subflow_fwd_byts"),
    ("Subflow Bwd Packets", "subflow_bwd_pkts"),
    ("Subflow Bwd Bytes", "subflow_bwd_byts"),
    ("Init Fwd Win Bytes", "init_fwd_win_byts"),
    ("Init Bwd Win Bytes", "init_bwd_win_byts"),
    ("Fwd Act Data Packets", "fwd_act_data_pkts"),
    ("Fwd Seg Size Min", "fwd_seg_size_min"),
    ("Active Mean", "active_mean"),
    ("Active Std", "active_std"),
    ("Active Max", "active_max"),
    ("Active Min", "active_min"),
    ("Idle Mean", "idle_mean"),
    ("Idle Std", "idle_std"),
    ("Idle Max", "idle_max"),
    ("Idle Min", "idle_min"),
]
CSV_FEATURE_COLS = [csv_col for _, csv_col in FEATURE_MAPPING]


# Setup HTTP Session dengan TLS1.2 agar tidak kena SSLEOFError
class TLS12Adapter(HTTPAdapter):

  def init_poolmanager(self, *args, **kwargs):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    kwargs["ssl_context"] = ctx
    return super().init_poolmanager(*args, **kwargs)


session = requests.Session()
session.mount("https://", TLS12Adapter())


def run_ingestion(rows_per_file=100):
  conn = psycopg2.connect(DATABASE_URL)
  cur = conn.cursor()

  csv_files = glob.glob("../attack_sim/*.csv")
  print(f"Ditemukan {len(csv_files)} file CSV. Memulai proses...\n")

  for filepath in csv_files:
    filename = os.path.basename(filepath)
    try:
      df = pd.read_csv(filepath, nrows=rows_per_file)
      if df.empty:
        continue

      # Siapkan 77 fitur sesuai urutan API Hilal
      X = df[CSV_FEATURE_COLS].replace([np.inf, -np.inf], np.nan).fillna(0.0)

      # Tembak ke API Hilal
      res = session.post(API_URL, json={"data": X.values.tolist()}, timeout=30)
      res.raise_for_status()
      pred_data = res.json()

      # Gabungkan metadata CSV + hasil prediksi API untuk masuk ke PostgreSQL
      records = []
      for i, row in df.iterrows():
        records.append((
            filename,
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

      insert_sql = """
                INSERT INTO intrusion_logs (
                    scenario_file, src_ip, dst_ip, src_port, dst_port, protocol,
                    flow_timestamp, flow_duration, total_packets,
                    prediction_code, prediction_label, attack_probability
                ) VALUES %s
            """
      execute_values(cur, insert_sql, records)
      conn.commit()
      print(
          f"[OK] {filename}: {len(records)} baris masuk PostgreSQL (Contoh"
          f" prediksi: {pred_data['labels'][0]})"
      )

    except Exception as e:
      conn.rollback()
      print(f"[SKIP] {filename}: {e}")

  cur.close()
  conn.close()
  print("\nSelesai! Data siap dipakai oleh Backend API.")


if __name__ == "__main__":
  run_ingestion(rows_per_file=100)
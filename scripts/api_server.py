# api_server.py
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import RootModel
import joblib
import pandas as pd
import os
from typing import List, Any, Dict

# -------------------------
# CONFIG
# -------------------------
PROJECT_ROOT = r"C:\Users\soham\OneDrive\Desktop\IDS IPS Project"
MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
SELECTED_FEATURES_PATH = os.path.join(PROJECT_ROOT, "data", "selected_features_dataset.csv")
RESULTS_CSV = os.path.join(PROJECT_ROOT, "results", "model_comparison.csv")

# -------------------------
# FASTAPI INIT
# -------------------------
app = FastAPI(title="IDS/IPS Prediction API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow all for local testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# LOAD SELECTED FEATURES
# -------------------------
if not os.path.exists(SELECTED_FEATURES_PATH):
    raise FileNotFoundError(f"Selected features file not found at: {SELECTED_FEATURES_PATH}")

_selected_df = pd.read_csv(SELECTED_FEATURES_PATH)
FEATURE_COLUMNS = [c for c in _selected_df.columns if c != "Label"]

print("\n✅ Expected features:")
for c in FEATURE_COLUMNS:
    print("  •", c)
print()

# -------------------------
# LOAD MODELS
# -------------------------
MODEL_BUNDLES: Dict[str, Dict[str, Any]] = {}

for fname in os.listdir(MODEL_DIR) if os.path.exists(MODEL_DIR) else []:
    if fname.lower().endswith(".pkl"):
        model_name = fname.replace("_model.pkl", "").replace(".pkl", "")
        path = os.path.join(MODEL_DIR, fname)
        try:
            bundle = joblib.load(path)
            if isinstance(bundle, dict) and "model" in bundle:
                MODEL_BUNDLES[model_name] = bundle
            else:
                MODEL_BUNDLES[model_name] = {"model": bundle, "label_encoder": None}
        except Exception as e:
            print(f"❌ Failed to load {path}: {e}")

if not MODEL_BUNDLES:
    print("⚠️ No models found in models directory. Start your models first.")

# -------------------------
# VALIDATION HELPERS
# -------------------------
def align_and_validate_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Align dataframe to model training columns.
    - Drops extra columns
    - Fills missing columns with 0
    - Ignores order mismatches
    """
    print("\n📊 Incoming payload columns:", list(df.columns))
    print("🧩 Expected model features:", FEATURE_COLUMNS)

    # Fix for slight naming inconsistencies (underscore vs space)
    rename_map = {}
    for c in df.columns:
        fixed = c.replace("_", " ").strip()
        rename_map[c] = fixed
    df.rename(columns=rename_map, inplace=True)

    # Keep only the expected columns
    df = df[[c for c in df.columns if c in FEATURE_COLUMNS]]

    # Fill any missing columns with 0
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            print(f"⚠️ Missing column '{col}' added with default 0")
            df[col] = 0.0

    # Reorder columns as model expects
    aligned = df.loc[:, FEATURE_COLUMNS].copy()

    print("✅ Final aligned columns:", list(aligned.columns))
    return aligned



def single_row_from_json(obj: Dict[str, Any]) -> pd.DataFrame:
    df = pd.DataFrame([obj])
    return align_and_validate_df(df)


def bundle_predict(bundle: Dict[str, Any], X: pd.DataFrame) -> List[str]:
    model = bundle.get("model")
    le_model = bundle.get("label_encoder", None)
    preds = model.predict(X)
    if le_model is not None:
        try:
            labels = le_model.inverse_transform(preds)
        except Exception:
            labels = preds
    else:
        labels = preds
    return [str(l) for l in labels]

# -------------------------
# ENDPOINTS
# -------------------------
@app.get("/models")
def list_models():
    return {"models": list(MODEL_BUNDLES.keys()), "feature_count": len(FEATURE_COLUMNS)}

@app.get("/metrics")
def get_metrics():
    if not os.path.exists(RESULTS_CSV):
        raise HTTPException(status_code=404, detail="Results CSV not found.")
    df = pd.read_csv(RESULTS_CSV)
    return {"metrics": df.to_dict(orient="records")}

@app.post("/predict")
def predict(payload: Any):
    print("\n===============================")
    print("📥 RAW PAYLOAD RECEIVED FROM FRONTEND:")
    print(payload)
    print("===============================")


@app.post("/predict_file")
def predict_file(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=415, detail="Only CSV files are supported.")
    try:
        contents = file.file.read()
        df = pd.read_csv(pd.io.common.BytesIO(contents))
        df_aligned = align_and_validate_df(df)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error reading CSV: {e}")

    predictions = []
    for idx in range(len(df_aligned)):
        row = df_aligned.iloc[[idx]]
        row_pred = {"row_index": idx}
        for model_name, bundle in MODEL_BUNDLES.items():
            try:
                row_pred[model_name] = bundle_predict(bundle, row)[0]
            except Exception as e:
                row_pred[model_name] = f"ERROR: {e}"
        predictions.append(row_pred)

    return {"predictions": predictions, "n_rows": len(df_aligned)}

@app.get("/")
def root():
    return {"message": "IDS/IPS Prediction API. Use POST /predict with JSON or /predict_file with CSV."}

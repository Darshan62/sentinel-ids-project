import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import os

# ================================
# CONFIGURATION
# ================================
DATA_PATH = r"E:\IDS IPS Project\data\train_processed.csv"
OUTPUT_PATH = r"E:\IDS IPS Project\data\selected_features_dataset.csv"
TOP_FEATURES_COUNT = 20

# ================================
# ATTACK TYPES TO KEEP
# ================================
TARGET_ATTACKS = [
    'BENIGN',
    'DoS Hulk',
    'DDoS',
    'DoS GoldenEye',
    'FTP-Patator',
    'SSH-Patator',
    'DoS slowloris',
    'Web Attack - Brute Force',
    'Web Attack - XSS',
    'Web Attack - Sql Injection'
]

print(" Loading preprocessed dataset...")
df = pd.read_csv(DATA_PATH)
print(f" Original shape: {df.shape}")

# ================================
# FILTER REQUIRED ATTACKS
# ================================
df = df[df['Label'].isin(TARGET_ATTACKS)]
print(f" After filtering attacks: {df.shape}")

# ================================
# SPLIT FEATURES & LABELS
# ================================
X = df.drop(columns=["Label"])
y = df["Label"]

# Encode string labels to numeric
le = LabelEncoder()
y_encoded = le.fit_transform(y)

# ================================
# FEATURE SELECTION USING RANDOM FOREST
# ================================
print(" Training Random Forest for feature importance...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
rf.fit(X, y_encoded)

importances = rf.feature_importances_
feature_importance_df = pd.DataFrame({
    'Feature': X.columns,
    'Importance': importances
}).sort_values(by='Importance', ascending=False)

# Select top N features
top_features = feature_importance_df.head(TOP_FEATURES_COUNT)['Feature'].tolist()
print(f"Top {TOP_FEATURES_COUNT} features selected:")
for i, f in enumerate(top_features, 1):
    print(f"{i}. {f}")

# ================================
# SAVE REDUCED DATASET
# ================================
selected_df = X[top_features]
selected_df['Label'] = y.values

os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
selected_df.to_csv(OUTPUT_PATH, index=False)
print(f" Reduced dataset saved at: {OUTPUT_PATH}")
print(f"Final dataset shape: {selected_df.shape}")

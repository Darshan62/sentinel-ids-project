import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import os


# CONFIGURATION

DATA_PATH = r"E:\IDS IPS Project\data\balanced_final_dataset.csv"
PROCESSED_TRAIN = r"E:\IDS IPS Project\data\train_processed.csv"
PROCESSED_TEST = r"E:\IDS IPS Project\data\test_processed.csv"


# LOAD DATA

print(" Loading dataset...")
df = pd.read_csv(DATA_PATH)

print(f" Original shape: {df.shape}")


# CLEANING
df = df.dropna()
df = df.replace([float('inf'), float('-inf')], 0)

# Drop duplicates (optional)
df = df.drop_duplicates()

print(f"🧹 After cleaning: {df.shape}")


# FEATURE / LABEL SPLIT

X = df.drop(columns=["Label"])
y = df["Label"]


# NORMALIZATION

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
X = pd.DataFrame(X_scaled, columns=X.columns)


# SPLIT DATASET

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

train_df = X_train.copy()
train_df["Label"] = y_train.values

test_df = X_test.copy()
test_df["Label"] = y_test.values

os.makedirs(os.path.dirname(PROCESSED_TRAIN), exist_ok=True)
train_df.to_csv(PROCESSED_TRAIN, index=False)
test_df.to_csv(PROCESSED_TEST, index=False)

print("Preprocessing complete.")
print(f" Train set: {PROCESSED_TRAIN}")
print(f" Test set:  {PROCESSED_TEST}")

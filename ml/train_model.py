import os
import re
import joblib
import pandas as pd

from urllib.parse import urlparse

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)


# =========================================================
# CONFIGURATION
# =========================================================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "ml", "model.pkl")

RANDOM_STATE = 42


# =========================================================
# SUSPICIOUS WORDS
# =========================================================

SUSPICIOUS_WORDS = [
    "password",
    "verify",
    "verification",
    "urgent",
    "bank",
    "login",
    "signin",
    "sign-in",
    "prize",
    "free",
    "account",
    "secure",
    "security",
    "confirm",
    "confirmation",
    "update",
    "wallet",
    "payment",
    "billing",
    "recover",
    "unlock",
    "claim",
    "bonus",
    "reward"
]


# =========================================================
# SUSPICIOUS PARAMETERS
# =========================================================

SUSPICIOUS_PARAMETERS = [
    "login",
    "signin",
    "password",
    "passwd",
    "verify",
    "verification",
    "account",
    "confirm",
    "confirmation",
    "bank",
    "payment",
    "wallet",
    "token",
    "session",
    "auth"
]


# =========================================================
# SUSPICIOUS TLDs
# =========================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf"
]


# =========================================================
# URL SHORTENERS
# =========================================================

URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd"
]


# =========================================================
# SUSPICIOUS FILE EXTENSIONS
# =========================================================

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".apk",
    ".scr",
    ".zip"
]


# =========================================================
# DOMAIN SUSPICIOUS WORDS
# =========================================================

DOMAIN_SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "bank",
    "payment",
    "signin",
    "security"
]


# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_features(url):

    url = str(url).strip()

    parsed_url = urlparse(url)

    domain = parsed_url.hostname or ""
    domain = domain.lower()

    url_lower = url.lower()

    path = parsed_url.path.lower()

    query = parsed_url.query.lower()

    features = []


    # =====================================================
    # 1. URL LENGTH
    # =====================================================

    features.append(len(url))


    # =====================================================
    # 2. NUMBER OF DOTS
    # =====================================================

    features.append(url.count("."))


    # =====================================================
    # 3. HYPHENS IN DOMAIN
    # =====================================================

    features.append(domain.count("-"))


    # =====================================================
    # 4. NUMBER OF DIGITS
    # =====================================================

    features.append(
        sum(c.isdigit() for c in url)
    )


    # =====================================================
    # 5. SPECIAL CHARACTERS
    # =====================================================

    features.append(
        sum(not c.isalnum() for c in url)
    )


    # =====================================================
    # 6. HTTPS
    # =====================================================

    if url_lower.startswith("https://"):
        features.append(1)
    else:
        features.append(0)


    # =====================================================
    # 7. IP ADDRESS
    # =====================================================

    if re.match(
        r"^\d+\.\d+\.\d+\.\d+$",
        domain
    ):
        features.append(1)
    else:
        features.append(0)


    # =====================================================
    # 8. SUSPICIOUS WORD COUNT
    # =====================================================

    suspicious_word_count = 0

    for word in SUSPICIOUS_WORDS:

        if word in url_lower:

            suspicious_word_count += 1

    features.append(
        suspicious_word_count
    )


    # =====================================================
    # 9. DOMAIN LENGTH
    # =====================================================

    features.append(
        len(domain)
    )


    # =====================================================
    # 10. SUBDOMAIN COUNT
    # =====================================================

    if domain:

        subdomain_count = max(
            len(domain.split(".")) - 2,
            0
        )

    else:

        subdomain_count = 0

    features.append(
        subdomain_count
    )


    # =====================================================
    # 11. SUSPICIOUS PARAMETER COUNT
    # =====================================================

    suspicious_parameter_count = 0

    for parameter in SUSPICIOUS_PARAMETERS:

        if parameter in query:

            suspicious_parameter_count += 1

    features.append(
        suspicious_parameter_count
    )


    # =====================================================
    # 12. @ SYMBOL
    # =====================================================

    if "@" in url:

        features.append(1)

    else:

        features.append(0)


    # =====================================================
    # 13. SUSPICIOUS TLD
    # =====================================================

    suspicious_tld = 0

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):

            suspicious_tld = 1

            break

    features.append(
        suspicious_tld
    )


    # =====================================================
    # 14. URL SHORTENER
    # =====================================================

    shortener = 0

    for service in URL_SHORTENERS:

        if domain == service:

            shortener = 1

            break

    features.append(
        shortener
    )


    # =====================================================
    # 15. SUSPICIOUS FILE EXTENSION
    # =====================================================

    suspicious_extension = 0

    clean_path = path.split("?")[0]

    for extension in SUSPICIOUS_EXTENSIONS:

        if clean_path.endswith(extension):

            suspicious_extension = 1

            break

    features.append(
        suspicious_extension
    )


    # =====================================================
    # 16. ENCODED CHARACTER
    # =====================================================

    if "%" in url:

        features.append(1)

    else:

        features.append(0)


    # =====================================================
    # 17. MULTIPLE // IN PATH
    # =====================================================

    if "//" in path:

        features.append(1)

    else:

        features.append(0)


    # =====================================================
    # 18. DOMAIN DIGIT COUNT
    # =====================================================

    features.append(
        sum(c.isdigit() for c in domain)
    )


    # =====================================================
    # 19. DOMAIN SPECIAL CHARACTER COUNT
    # =====================================================

    features.append(
        sum(
            not c.isalnum() and c != "."
            for c in domain
        )
    )


    # =====================================================
    # 20. PATH LENGTH
    # =====================================================

    features.append(
        len(path)
    )


    # =====================================================
    # 21. QUERY LENGTH
    # =====================================================

    features.append(
        len(query)
    )


    # =====================================================
    # 22. SUSPICIOUS WORDS IN DOMAIN
    # =====================================================

    domain_word_count = 0

    for word in DOMAIN_SUSPICIOUS_WORDS:

        if word in domain:

            domain_word_count += 1

    features.append(
        domain_word_count
    )


    return features


# =========================================================
# MAIN TRAINING PROCESS
# =========================================================

print()
print("==============================")
print("🛡️ FRAUDSHIELD AI ML TRAINING")
print("==============================")
print()


# =========================================================
# LOAD DATASET
# =========================================================

print("Loading dataset...")

try:

    data = pd.read_csv(
        DATASET_PATH
    )

except FileNotFoundError:

    print(
        f"❌ Dataset not found: {DATASET_PATH}"
    )

    raise SystemExit


print("✅ Dataset loaded!")


# =========================================================
# DATASET INFORMATION
# =========================================================

print()
print("Dataset shape:")
print(data.shape)

print()
print("Dataset columns:")
print(list(data.columns))


# =========================================================
# CHECK REQUIRED COLUMNS
# =========================================================

required_columns = [
    "url",
    "label"
]

for column in required_columns:

    if column not in data.columns:

        print(
            f"❌ Required column '{column}' "
            "was not found in dataset.csv"
        )

        raise SystemExit


# =========================================================
# CLEAN DATA
# =========================================================

data = data.dropna(
    subset=[
        "url",
        "label"
    ]
)

data["url"] = data["url"].astype(str)

data["label"] = pd.to_numeric(
    data["label"],
    errors="coerce"
)

data = data.dropna(
    subset=["label"]
)

data["label"] = data["label"].astype(int)


print()
print(
    "Rows after cleaning:",
    len(data)
)


# =========================================================
# LABEL DISTRIBUTION
# =========================================================

print()
print("Label distribution:")

print(
    data["label"].value_counts()
)


# =========================================================
# FEATURE EXTRACTION
# =========================================================

print()
print("Extracting URL features...")

X = data["url"].apply(
    extract_features
)

X = list(X)

y = data["label"]


print(
    "✅ Feature extraction completed!"
)


print()
print(
    "Number of ML features:",
    len(X[0])
)


# =========================================================
# FEATURE NAMES
# =========================================================

feature_names = [

    "url_length",

    "dot_count",

    "domain_hyphen_count",

    "digit_count",

    "special_character_count",

    "https",

    "ip_address",

    "suspicious_word_count",

    "domain_length",

    "subdomain_count",

    "suspicious_parameter_count",

    "at_symbol",

    "suspicious_tld",

    "url_shortener",

    "suspicious_file_extension",

    "encoded_character",

    "multiple_slashes",

    "domain_digit_count",

    "domain_special_character_count",

    "path_length",

    "query_length",

    "domain_suspicious_word_count"

]


# =========================================================
# VERIFY FEATURE COUNT
# =========================================================

if len(X[0]) != len(feature_names):

    print()
    print(
        "❌ Feature count mismatch!"
    )

    print(
        "Extracted:",
        len(X[0])
    )

    print(
        "Expected:",
        len(feature_names)
    )

    raise SystemExit


# =========================================================
# DISPLAY FEATURE ORDER
# =========================================================

print()
print("Feature order:")

for index, name in enumerate(
    feature_names,
    start=1
):

    print(
        f"{index}. {name}"
    )


# =========================================================
# SPLIT DATA
# =========================================================

print()
print("Splitting dataset...")


X_train, X_test, y_train, y_test = train_test_split(

    X,

    y,

    test_size=0.20,

    random_state=RANDOM_STATE,

    stratify=y
)


print(
    "Training samples:",
    len(X_train)
)

print(
    "Testing samples :",
    len(X_test)
)


# =========================================================
# CREATE RANDOM FOREST
# =========================================================

print()
print("Creating Random Forest model...")


model = RandomForestClassifier(

    n_estimators=300,

    max_depth=None,

    min_samples_split=2,

    min_samples_leaf=1,

    class_weight="balanced",

    random_state=RANDOM_STATE,

    n_jobs=-1
)


# =========================================================
# TRAIN MODEL
# =========================================================

print(
    "Training model..."
)

print()


model.fit(

    X_train,

    y_train
)


print(
    "✅ Model training completed!"
)


# =========================================================
# PREDICTIONS
# =========================================================

predictions = model.predict(
    X_test
)


# =========================================================
# PROBABILITIES
# =========================================================

probabilities = model.predict_proba(
    X_test
)


# =========================================================
# MODEL EVALUATION
# =========================================================

accuracy = accuracy_score(

    y_test,

    predictions
)


precision = precision_score(

    y_test,

    predictions,

    zero_division=0
)


recall = recall_score(

    y_test,

    predictions,

    zero_division=0
)


f1 = f1_score(

    y_test,

    predictions,

    zero_division=0
)


cm = confusion_matrix(

    y_test,

    predictions
)


# =========================================================
# DISPLAY RESULTS
# =========================================================

print()
print("==============================")
print("📊 MODEL EVALUATION")
print("==============================")


print(
    f"Accuracy : {accuracy:.4f}"
)


print(
    f"Precision: {precision:.4f}"
)


print(
    f"Recall   : {recall:.4f}"
)


print(
    f"F1 Score : {f1:.4f}"
)


print()
print("Confusion Matrix:")

print(cm)


print()
print("Classification Report:")

print(
    classification_report(

        y_test,

        predictions,

        target_names=[
            "Legitimate",
            "Phishing"
        ],

        zero_division=0
    )
)


# =========================================================
# FEATURE IMPORTANCE
# =========================================================

print()
print("==============================")
print("🌲 FEATURE IMPORTANCE")
print("==============================")


importance = model.feature_importances_


feature_importance = sorted(

    zip(
        feature_names,
        importance
    ),

    key=lambda x: x[1],

    reverse=True
)


for name, value in feature_importance:

    print(
        f"{name:35s} : {value:.4f}"
    )


# =========================================================
# SAVE MODEL
# =========================================================

os.makedirs(

    os.path.dirname(MODEL_PATH),

    exist_ok=True
)


joblib.dump(

    model,

    MODEL_PATH
)


print()
print("==============================")
print("✅ MODEL SAVED")
print("==============================")


print(
    f"Model saved to: {MODEL_PATH}"
)


print()
print(
    "🛡️ FraudShield AI ML training completed!"
)
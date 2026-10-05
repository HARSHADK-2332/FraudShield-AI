from urllib.parse import urlparse
import re
from difflib import SequenceMatcher


# =========================================================
# SUSPICIOUS WORDS
# =========================================================

SUSPICIOUS_WORDS = {
    "password": 15,
    "verify": 12,
    "urgent": 12,
    "bank": 10,
    "login": 8,
    "prize": 8,
    "free": 5,
}


# =========================================================
# SUSPICIOUS PARAMETERS
# =========================================================

SUSPICIOUS_PARAMETERS = [
    "password",
    "passwd",
    "token",
    "session",
    "redirect",
    "return",
    "verify",
    "login",
]


# =========================================================
# SUSPICIOUS DOMAIN WORDS
# =========================================================

SUSPICIOUS_DOMAIN_WORDS = [
    "secure",
    "account",
    "verify",
    "verification",
    "login",
    "signin",
    "update",
    "confirm",
    "support",
    "security",
]


# =========================================================
# SUSPICIOUS TLDs
# =========================================================

SUSPICIOUS_TLDS = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
]


# =========================================================
# URL SHORTENERS
# =========================================================

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
]


# =========================================================
# SUSPICIOUS FILE EXTENSIONS
# =========================================================

SUSPICIOUS_EXTENSIONS = [
    ".exe",
    ".apk",
    ".scr",
    ".zip",
]


# =========================================================
# LOOKALIKE CHARACTER MAPPING
# =========================================================

LOOKALIKE_PATTERNS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
}


# =========================================================
# HIGH-RISK WORD COMBINATIONS
# =========================================================

HIGH_RISK_COMBINATIONS = [
    ("verify", "password"),
    ("login", "password"),
    ("bank", "login"),
    ("urgent", "verify"),
    ("urgent", "login"),
    ("verify", "bank"),
    ("account", "verify"),
    ("payment", "verify"),
]


# =========================================================
# ML FEATURE EXTRACTION
# =========================================================

def extract_ml_features(url):
    """
    Extract the exact 22 features used by
    ml/train_model.py.

    IMPORTANT:
    The feature order must remain exactly the same
    as the training file.
    """

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
    # 2. DOT COUNT
    # =====================================================

    features.append(url.count("."))

    # =====================================================
    # 3. DOMAIN HYPHEN COUNT
    # =====================================================

    features.append(domain.count("-"))

    # =====================================================
    # 4. DIGIT COUNT
    # =====================================================

    features.append(
        sum(
            character.isdigit()
            for character in url
        )
    )

    # =====================================================
    # 5. SPECIAL CHARACTER COUNT
    # =====================================================

    features.append(
        sum(
            not character.isalnum()
            for character in url
        )
    )

    # =====================================================
    # 6. HTTPS
    # =====================================================

    features.append(
        1 if url_lower.startswith("https://") else 0
    )

    # =====================================================
    # 7. IP ADDRESS
    # =====================================================

    features.append(
        1
        if re.match(
            r"^\d+\.\d+\.\d+\.\d+$",
            domain
        )
        else 0
    )

    # =====================================================
    # 8. SUSPICIOUS WORD COUNT
    # =====================================================

    suspicious_words = [
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
        "reward",
    ]

    suspicious_word_count = 0

    for word in suspicious_words:
        if word in url_lower:
            suspicious_word_count += 1

    features.append(suspicious_word_count)

    # =====================================================
    # 9. DOMAIN LENGTH
    # =====================================================

    features.append(len(domain))

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

    features.append(subdomain_count)

    # =====================================================
    # 11. SUSPICIOUS PARAMETER COUNT
    # =====================================================

    suspicious_parameters = [
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
        "auth",
    ]

    suspicious_parameter_count = 0

    for parameter in suspicious_parameters:
        if parameter in query:
            suspicious_parameter_count += 1

    features.append(suspicious_parameter_count)

    # =====================================================
    # 12. @ SYMBOL
    # =====================================================

    features.append(
        1 if "@" in url else 0
    )

    # =====================================================
    # 13. SUSPICIOUS TLD
    # =====================================================

    suspicious_tld = 0

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            suspicious_tld = 1
            break

    features.append(suspicious_tld)

    # =====================================================
    # 14. URL SHORTENER
    # =====================================================

    shortener = 0

    for service in SHORTENERS:
        if domain == service:
            shortener = 1
            break

    features.append(shortener)

    # =====================================================
    # 15. SUSPICIOUS FILE EXTENSION
    # =====================================================

    suspicious_extension = 0

    clean_path = path.split("?")[0]

    for extension in SUSPICIOUS_EXTENSIONS:
        if clean_path.endswith(extension):
            suspicious_extension = 1
            break

    features.append(suspicious_extension)

    # =====================================================
    # 16. ENCODED CHARACTER
    # =====================================================

    features.append(
        1 if "%" in url else 0
    )

    # =====================================================
    # 17. MULTIPLE SLASHES
    # =====================================================

    features.append(
        1 if "//" in path else 0
    )

    # =====================================================
    # 18. DOMAIN DIGIT COUNT
    # =====================================================

    features.append(
        sum(
            character.isdigit()
            for character in domain
        )
    )

    # =====================================================
    # 19. DOMAIN SPECIAL CHARACTER COUNT
    # =====================================================

    features.append(
        sum(
            not character.isalnum()
            and character != "."
            for character in domain
        )
    )

    # =====================================================
    # 20. PATH LENGTH
    # =====================================================

    features.append(len(path))

    # =====================================================
    # 21. QUERY LENGTH
    # =====================================================

    features.append(len(query))

    # =====================================================
    # 22. SUSPICIOUS WORDS IN DOMAIN
    # =====================================================

    domain_suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "bank",
        "payment",
        "signin",
        "security",
    ]

    domain_word_count = 0

    for word in domain_suspicious_words:
        if word in domain:
            domain_word_count += 1

    features.append(domain_word_count)

    return features


# =========================================================
# URL ANALYSIS
# =========================================================

def analyze_url(url, safe_domains, threat_domains):
    """
    Analyze a URL using the FraudShield rule engine.

    Returns a dictionary containing:

        score
        risk_level
        reasons
        domain
        rule_score
        critical_threat
        strong_threat
    """

    score = 0
    reasons = []

    critical_threat = False
    strong_threat = False

    url = url.strip()

    # =====================================================
    # URL VALIDATION
    # =====================================================

    if not url.startswith(("http://", "https://")):
        return {
            "valid": False,
            "error": (
                "Please enter a valid URL starting "
                "with http:// or https://"
            ),
        }

    parsed_url = urlparse(url)

    domain = parsed_url.hostname

    if not domain:
        return {
            "valid": False,
            "error": "Invalid URL.",
        }

    domain = domain.lower()

    # =====================================================
    # SAFE DOMAIN
    # =====================================================

    if domain in safe_domains:
        reasons.append(
            "✅ Domain exists in trusted database."
        )

    # =====================================================
    # KNOWN THREAT
    # =====================================================

    if domain in threat_domains:

        score += 50

        critical_threat = True

        threat_type = threat_domains[domain]

        reasons.append(
            f"🚨 Known threat detected: {threat_type}"
        )

    # =====================================================
    # DOMAIN SIMILARITY
    # =====================================================

    current_name = domain.split(".")[0]

    for safe_domain in safe_domains:

        safe_name = safe_domain.split(".")[0]

        similarity = SequenceMatcher(
            None,
            current_name,
            safe_name,
        ).ratio()

        if (
            similarity >= 0.80
            and current_name != safe_name
        ):

            score += 35

            strong_threat = True

            reasons.append(
                "🚨 Domain is very similar to trusted domain: "
                + safe_domain
            )

            break

    # =====================================================
    # LOOKALIKE DOMAIN
    # =====================================================

    converted_name = current_name

    lookalike_found = False

    for number, letter in LOOKALIKE_PATTERNS.items():

        if number in current_name:

            lookalike_found = True

            converted_name = converted_name.replace(
                number,
                letter,
            )

    if lookalike_found:

        score += 15

        reasons.append(
            "⚠️ Possible lookalike domain detected."
        )

        for safe_domain in safe_domains:

            safe_name = safe_domain.split(".")[0]

            if converted_name == safe_name:

                score += 35

                strong_threat = True

                reasons.append(
                    "🚨 Domain may be impersonating "
                    + safe_domain
                )

                break

    # =====================================================
    # BASIC URL FEATURES
    # =====================================================

    url_length = len(url)

    dot_count = url.count(".")

    hyphen_count = domain.count("-")

    digit_count = sum(
        character.isdigit()
        for character in url
    )

    special_count = sum(
        not character.isalnum()
        for character in url
    )

    # =====================================================
    # MANY NUMBERS
    # =====================================================

    if digit_count >= 5:

        score += 10

        reasons.append(
            "⚠️ URL contains many numbers."
        )

    # =====================================================
    # MANY HYPHENS
    # =====================================================

    if hyphen_count >= 3:

        score += 10

        reasons.append(
            "⚠️ Domain contains many hyphens."
        )

    # =====================================================
    # MANY DOTS
    # =====================================================

    if dot_count >= 4:

        score += 10

        reasons.append(
            "⚠️ URL contains many dots."
        )

    # =====================================================
    # SPECIAL CHARACTERS
    # =====================================================

    if special_count >= 10:

        score += 10

        reasons.append(
            "⚠️ URL contains many special characters."
        )

    # =====================================================
    # HTTPS
    # =====================================================

    if not url.startswith("https://"):

        score += 20

        reasons.append(
            "❌ HTTPS is not enabled."
        )

    else:

        reasons.append(
            "✅ HTTPS enabled."
        )

    # =====================================================
    # URL LENGTH
    # =====================================================

    if url_length > 75:

        score += 15

        reasons.append(
            "⚠️ URL is very long."
        )

    # =====================================================
    # SUSPICIOUS PARAMETERS
    # =====================================================

    query = parsed_url.query.lower()

    found_parameters = []

    for parameter in SUSPICIOUS_PARAMETERS:

        if parameter in query:

            found_parameters.append(parameter)

    if len(found_parameters) >= 2:

        score += 15

        strong_threat = True

        reasons.append(
            "🚨 Multiple suspicious URL parameters: "
            + ", ".join(found_parameters)
        )

    # =====================================================
    # SUSPICIOUS WORDS
    # =====================================================

    found_words = []

    lower_url = url.lower()

    for word, points in SUSPICIOUS_WORDS.items():

        if word in lower_url:

            found_words.append(word)

            score += points

    if found_words:

        reasons.append(
            "⚠️ Suspicious words detected: "
            + ", ".join(found_words)
        )

    # =====================================================
    # HIGH-RISK COMBINATIONS
    # =====================================================

    for word1, word2 in HIGH_RISK_COMBINATIONS:

        if (
            word1 in lower_url
            and word2 in lower_url
        ):

            score += 20

            strong_threat = True

            reasons.append(
                f"🚨 High-risk combination: "
                f"{word1} + {word2}"
            )

    # =====================================================
    # IP ADDRESS
    # =====================================================

    is_ip_address = bool(
        re.match(
            r"^\d+\.\d+\.\d+\.\d+$",
            domain
        )
    )

    if is_ip_address:

        score += 25

        strong_threat = True

        reasons.append(
            "🚨 URL uses an IP address instead of a domain."
        )

    # =====================================================
    # SUSPICIOUS DOMAIN WORDS
    # =====================================================

    found_domain_words = []

    for word in SUSPICIOUS_DOMAIN_WORDS:

        if word in domain:

            found_domain_words.append(word)

    if len(found_domain_words) >= 2:

        score += 15

        strong_threat = True

        reasons.append(
            "🚨 Domain contains multiple suspicious "
            "security-related words: "
            + ", ".join(found_domain_words)
        )

    # =====================================================
    # DOMAIN LENGTH
    # =====================================================

    if len(domain) > 30:

        score += 10

        reasons.append(
            "⚠️ Domain name is very long."
        )

    # =====================================================
    # SUBDOMAINS
    # =====================================================

    if domain.count(".") > 2:

        score += 10

        reasons.append(
            "⚠️ URL contains many subdomains."
        )

    # =====================================================
    # SUSPICIOUS TLD
    # =====================================================

    for tld in SUSPICIOUS_TLDS:

        if domain.endswith(tld):

            score += 15

            reasons.append(
                "⚠️ Suspicious domain extension: "
                + tld
            )

            break

    # =====================================================
    # @ SYMBOL
    # =====================================================

    if "@" in url:

        score += 20

        strong_threat = True

        reasons.append(
            "🚨 URL contains an @ symbol."
        )

    # =====================================================
    # SHORTENER
    # =====================================================

    if domain in SHORTENERS:

        score += 20

        strong_threat = True

        reasons.append(
            "🚨 URL uses a shortened link."
        )

    # =====================================================
    # SUSPICIOUS FILE
    # =====================================================

    clean_url = url.lower().split("?")[0]

    if any(
        clean_url.endswith(extension)
        for extension in SUSPICIOUS_EXTENSIONS
    ):

        score += 20

        strong_threat = True

        reasons.append(
            "🚨 URL points to a potentially dangerous "
            "file type."
        )

    # =====================================================
    # ENCODED CHARACTERS
    # =====================================================

    if "%" in url:

        score += 10

        reasons.append(
            "⚠️ URL contains encoded characters."
        )

    # =====================================================
    # MULTIPLE //
    # =====================================================

    if "//" in parsed_url.path:

        score += 10

        reasons.append(
            "⚠️ URL contains multiple // characters."
        )

    # =====================================================
    # STRONG COMBINATION BOOST
    # =====================================================

    suspicious_signal_count = 0

    if not url.startswith("https://"):
        suspicious_signal_count += 1

    if found_words:
        suspicious_signal_count += 1

    if found_domain_words:
        suspicious_signal_count += 1

    if lookalike_found:
        suspicious_signal_count += 1

    if "@" in url:
        suspicious_signal_count += 1

    if domain in SHORTENERS:
        suspicious_signal_count += 1

    if is_ip_address:
        suspicious_signal_count += 1

    if suspicious_signal_count >= 3:

        score += 20

        strong_threat = True

        reasons.append(
            "🚨 Multiple independent phishing indicators "
            "were detected together."
        )

    # =====================================================
    # HARD RISK CONDITIONS
    # =====================================================

    if critical_threat:

        score = max(score, 70)

    if strong_threat:

        score = max(score, 50)

    # Keep score between 0 and 100

    score = min(score, 100)

    # =====================================================
    # RISK LEVEL
    # =====================================================

    if score >= 60:

        risk_level = "🔴 HIGH RISK"

    elif score >= 30:

        risk_level = "🟡 MEDIUM RISK"

    else:

        risk_level = "🟢 LOW RISK"

    # =====================================================
    # EXPLANATION
    # =====================================================

    if score >= 60:

        explanation = (
            "🚨 This URL shows multiple suspicious patterns. "
            "Avoid opening it or entering personal information."
        )

    elif score >= 30:

        explanation = (
            "⚠️ This URL shows some suspicious patterns. "
            "Verify the website carefully before continuing."
        )

    else:

        explanation = (
            "✅ No major suspicious patterns were detected "
            "by the rule engine."
        )

    # =====================================================
    # RECOMMENDATION
    # =====================================================

    if score >= 60:

        recommendation = (
            "🚫 Do not open this link. "
            "Do not enter personal or banking information."
        )

    elif score >= 30:

        recommendation = (
            "⚠️ Be careful. Verify the website through "
            "an official source before entering information."
        )

    else:

        recommendation = (
            "✅ No major suspicious patterns detected. "
            "Still verify the website before sharing "
            "sensitive information."
        )

    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {
        "valid": True,
        "domain": domain,
        "url_length": url_length,
        "dot_count": dot_count,
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "special_count": special_count,
        "rule_score": score,
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "explanation": explanation,
        "recommendation": recommendation,
        "critical_threat": critical_threat,
        "strong_threat": strong_threat,
    }
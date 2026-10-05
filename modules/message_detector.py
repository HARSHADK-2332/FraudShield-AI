
import re


def analyze_message(message):

    message = message.strip()

    score = 0
    reasons = []

    if not message:
        return {
            "score": 0,
            "risk_level": "LOWER RISK",
            "reasons": ["No message was provided."]
        }

    text = message.lower()

    # Urgency / pressure
    urgency_words = [
        "urgent",
        "immediately",
        "act now",
        "last chance",
        "within 24 hours",
        "account will be blocked",
        "account will be suspended"
    ]

    urgency_found = any(word in text for word in urgency_words)

    if urgency_found:
        score += 15
        reasons.append(
            "Message uses urgency or pressure to encourage immediate action."
        )

    # OTP request
    otp_words = [
        "otp",
        "one time password",
        "verification code",
        "security code"
    ]

    otp_found = any(word in text for word in otp_words)

    if otp_found:
        score += 25
        reasons.append(
            "Message requests or refers to an OTP or verification code."
        )

    # Password / account information
    sensitive_words = [
        "password",
        "pin",
        "cvv",
        "card number",
        "account number",
        "bank details",
        "login details"
    ]

    if any(word in text for word in sensitive_words):
        score += 25
        reasons.append(
            "Message requests sensitive account or banking information."
        )

    # Payment request
    payment_words = [
        "pay now",
        "send money",
        "payment",
        "transfer money",
        "upi",
        "pay",
        "fee",
        "processing fee"
    ]

    payment_found = any(word in text for word in payment_words)

    if payment_found:
        score += 20
        reasons.append(
            "Message contains a payment or money-transfer request."
        )

    # Threats
    threat_words = [
        "blocked",
        "suspended",
        "legal action",
        "police",
        "arrest",
        "penalty",
        "fine",
        "account closed"
    ]

    if any(word in text for word in threat_words):
        score += 20
        reasons.append(
            "Message contains threats, penalties, or account consequences."
        )

    # Suspicious links
    urls = re.findall(
        r"https?://\S+|www\.\S+",
        text
    )

    if urls:
        score += 20
        reasons.append(
            "Message contains a link that should be verified before opening."
        )

    # URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd"
    ]

    if any(domain in text for domain in shorteners):
        score += 15
        reasons.append(
            "Message contains a URL-shortening service."
        )

    # Prize / reward scams
    reward_words = [
        "you won",
        "winner",
        "congratulations",
        "prize",
        "reward",
        "lottery",
        "cashback",
        "free gift"
    ]

    if any(word in text for word in reward_words):
        score += 15
        reasons.append(
            "Message contains prize, reward, or lottery-related language."
        )

    # Impersonation
    organizations = [
        "bank",
        "police",
        "government",
        "income tax",
        "courier",
        "delivery",
        "amazon",
        "flipkart",
        "paypal"
    ]

    if any(word in text for word in organizations):
        score += 10
        reasons.append(
            "Message appears to mention an organization or authority."
        )

    # Suspicious combination: OTP + payment
    if otp_found and payment_found:
        score += 10
        reasons.append(
            "OTP-related language is combined with a payment request."
        )

    # Suspicious combination: urgency + link
    if urls and urgency_found:
        score += 10
        reasons.append(
            "Urgency is combined with a link."
        )

    # Limit score to 100
    score = min(score, 100)

    # Determine risk level
    if score >= 60:
        risk_level = "HIGH"
    elif score >= 30:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "LOWER RISK"

    return {
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }


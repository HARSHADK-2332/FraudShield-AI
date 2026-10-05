
import re


def validate_phone_number(phone):

    phone = phone.strip()

    if not phone:
        return False

    # Allows numbers such as:
    # +919876543210
    # 919876543210
    # 9876543210

    cleaned = re.sub(r"[\s\-()]", "", phone)

    if cleaned.startswith("+"):
        cleaned = cleaned[1:]

    if not cleaned.isdigit():
        return False

    if len(cleaned) < 10 or len(cleaned) > 15:
        return False

    return True


def analyze_call(
    phone_number,
    caller_claim,
    asked_otp,
    asked_bank_details,
    demanded_payment,
    threatened_user,
    impersonated
):

    score = 0
    reasons = []

    # OTP request
    if asked_otp:
        score += 25
        reasons.append(
            "Caller requested an OTP."
        )

    # Banking/card information
    if asked_bank_details:
        score += 25
        reasons.append(
            "Caller requested banking or card information."
        )

    # Payment demand
    if demanded_payment:
        score += 20
        reasons.append(
            "Caller demanded immediate payment."
        )

    # Threats / pressure
    if threatened_user:
        score += 20
        reasons.append(
            "Caller used threats or pressure."
        )

    # Impersonation
    if impersonated:
        score += 15
        reasons.append(
            "Caller appeared to impersonate an organization or authority."
        )

    # Bank impersonation
    if caller_claim == "Bank":
        if asked_otp or asked_bank_details:
            score += 10
            reasons.append(
                "Caller claimed to represent a bank while requesting sensitive information."
            )

    # Police / Government impersonation
    elif caller_claim == "Police/Government":
        if threatened_user or demanded_payment:
            score += 10
            reasons.append(
                "Caller used government/police identity together with pressure or payment demands."
            )

    # Delivery company scam
    elif caller_claim == "Delivery Company":
        if demanded_payment:
            score += 10
            reasons.append(
                "Caller claimed to be a delivery service and demanded payment."
            )

    # Job / recruitment scam
    elif caller_claim == "Job/Recruitment":
        if demanded_payment:
            score += 10
            reasons.append(
                "Caller claimed to offer a job while requesting payment."
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
        "phone_number": phone_number,
        "score": score,
        "risk_level": risk_level,
        "reasons": reasons
    }

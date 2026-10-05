
import re

from modules.url_detector import analyze_url
from modules.call_detector import analyze_call
from modules.message_detector import analyze_message


def detect_input_type(text):
    """
    Detect whether the user entered a URL,
    call-related information, or a message.
    """

    text = text.strip().lower()

    if not text:
        return "unknown"

    # URL detection
    url_pattern = r"https?://\S+|www\.\S+"

    if re.search(url_pattern, text):
        return "url"

    # Call-related keywords
    call_keywords = [
        "called me",
        "call me",
        "phone call",
        "caller",
        "someone called",
        "called saying",
        "called and asked",
        "received a call",
        "phone number",
        "someone phoned",
        "phoned me",
        "got a call"
    ]

    if any(keyword in text for keyword in call_keywords):
        return "call"

    # Otherwise treat it as a message
    return "message"


def get_help_response():

    return """
👋 Welcome to FraudShield AI!

I can help you detect suspicious URLs, calls, and messages.

🔗 URL Detection

Paste a suspicious website link here.

📞 Call Detection

Tell me what the caller said and what information they requested.

💬 Message Detection

Paste a suspicious SMS, email, or chat message.

🤖 AI Chatbot

You can also simply describe your problem here and I will help
you understand what to do.

You can ask questions such as:

• How do I use FraudShield?
• Someone asked for my OTP. What should I do?
• I received a suspicious bank message.
• How can I identify a phishing link?
• What should I do if I clicked a suspicious link?

🛡️ Never share your real OTP, password, PIN, CVV,
or other sensitive information.
"""


def get_safety_advice(risk_level):

    if risk_level == "HIGH":

        return """
🚨 Safety Recommendation:

• Do not click suspicious links.
• Do not share OTPs, passwords, PINs, or CVVs.
• Do not send money to the caller or sender.
• Do not provide banking information.
• Verify the organization using its official website or phone number.
"""

    elif risk_level == "SUSPICIOUS":

        return """
⚠️ Safety Recommendation:

• Be careful before responding.
• Do not share sensitive information.
• Verify the sender or caller independently.
• Avoid clicking links until they are verified.
• Do not make payments until the request is confirmed.
"""

    return """
✅ Safety Recommendation:

No strong fraud indicators were detected.

Still, avoid sharing passwords, OTPs, PINs, CVVs,
or banking information with unknown people.
"""


def get_general_response(text):

    text = text.lower()

    # Website help
    if any(word in text for word in [
        "how to use",
        "how do i use",
        "use this website",
        "use fraudshield",
        "how does this work",
        "how can i use",
        "how can i check"
    ]):

        return get_help_response()

    # OTP question
    if "otp" in text:

        return """
🔐 OTP Safety

Never share your OTP with anyone over a call, message, or chat.

If someone is asking for your OTP, treat the request as suspicious.

Verify the situation through the organization's official
website or official customer-support number.
"""

    # Suspicious link already clicked
    if any(word in text for word in [
        "clicked a link",
        "clicked the link",
        "opened the link",
        "i clicked",
        "i opened"
    ]):

        return """
⚠️ If you clicked a suspicious link:

1. Do not enter any more information.
2. Close the suspicious website.
3. If you entered a password, change it from the official website.
4. If banking information may be exposed, contact your bank
   using its official contact details.
5. Monitor your accounts for unusual activity.
"""

    # Phishing question
    if any(word in text for word in [
        "phishing",
        "phishing link"
    ]):

        return """
🎣 Phishing links often try to:

• Create urgency.
• Ask for passwords or OTPs.
• Request payments.
• Impersonate banks or organizations.
• Direct you to suspicious websites.

You can paste the suspicious URL here and
FraudShield can analyze it.
"""

    # Payment safety
    if any(word in text for word in [
        "send money",
        "transfer money",
        "pay someone",
        "payment scam",
        "payment fraud"
    ]):

        return """
💰 Payment Safety

Be careful when someone unexpectedly asks you to send money.

Before making a payment:

1. Verify who requested it.
2. Verify the organization independently.
3. Do not share OTPs or PINs.
4. Do not allow someone to pressure you into paying immediately.
"""

    # Greeting
    if any(word in text for word in [
        "hello",
        "hi",
        "hey",
        "hii",
        "hello there"
    ]):

        return """
👋 Hey! Welcome to FraudShield AI.

Paste a suspicious URL, suspicious message,
or describe a suspicious call and I'll help you analyze it.

You can also ask me:

"How do I use FraudShield?"
"""

    return """
🤖 I can help you analyze suspicious URLs, calls, and messages.

Try one of these:

🔗 Paste a suspicious URL

💬 Paste a suspicious message

📞 Describe what a caller asked you

❓ Ask "How do I use FraudShield?"

🛡️ You can also simply describe what happened
and I'll guide you.
"""


def analyze_chat_input(
    user_input,
    safe_domains=None,
    threat_domains=None
):
    """
    Analyze user input using the existing FraudShield detectors.
    """

    input_type = detect_input_type(user_input)

    # ---------------------------------------------------------
    # URL ANALYSIS
    # ---------------------------------------------------------

    if input_type == "url":

        if safe_domains is None:
            safe_domains = set()

        if threat_domains is None:
            threat_domains = {}

        result = analyze_url(
            user_input.strip(),
            safe_domains,
            threat_domains
        )

        # URL detector may use rule_score internally.
        score = result.get(
            "score",
            result.get("rule_score", 0)
        )

        risk_level = result.get(
            "risk_level",
            "LOWER RISK"
        )

        reasons = result.get(
            "reasons",
            []
        )

        return {
            "type": "URL",
            "score": score,
            "risk_level": risk_level,
            "reasons": reasons
        }

    # ---------------------------------------------------------
    # MESSAGE ANALYSIS
    # ---------------------------------------------------------

    if input_type == "message":

        result = analyze_message(user_input)

        return {
            "type": "MESSAGE",
            "score": result.get(
                "score",
                0
            ),
            "risk_level": result.get(
                "risk_level",
                "LOWER RISK"
            ),
            "reasons": result.get(
                "reasons",
                []
            )
        }

    # ---------------------------------------------------------
    # CALL ANALYSIS
    # ---------------------------------------------------------

    if input_type == "call":

        text = user_input.lower()

        # OTP
        asked_otp = any(word in text for word in [
            "otp",
            "one time password",
            "verification code",
            "security code"
        ])

        # Banking information
        asked_bank_details = any(word in text for word in [
            "bank details",
            "bank account",
            "account details",
            "card number",
            "card details",
            "cvv",
            "pin",
            "account number"
        ])

        # Payment
        demanded_payment = any(word in text for word in [
            "pay",
            "payment",
            "send money",
            "transfer money",
            "transfer",
            "upi",
            "fee",
            "processing fee"
        ])

        # Threat / pressure
        threatened_user = any(word in text for word in [
            "blocked",
            "block your account",
            "suspended",
            "account will be closed",
            "police",
            "arrest",
            "legal action",
            "penalty",
            "fine",
            "threat",
            "threatened",
            "immediately"
        ])

        # Impersonation
        impersonated = any(word in text for word in [
            "bank",
            "police",
            "government",
            "amazon",
            "flipkart",
            "courier",
            "delivery",
            "company",
            "officer",
            "customer care",
            "customer support"
        ])

        # Determine caller type
        caller_claim = "Other"

        if "bank" in text:

            caller_claim = "Bank"

        elif (
            "police" in text
            or "government" in text
            or "officer" in text
        ):

            caller_claim = "Police/Government"

        elif (
            "delivery" in text
            or "courier" in text
        ):

            caller_claim = "Delivery Company"

        elif (
            "job" in text
            or "recruitment" in text
            or "recruiter" in text
        ):

            caller_claim = "Job/Recruitment"

        elif (
            "telecom" in text
            or "mobile company" in text
            or "network company" in text
        ):

            caller_claim = "Telecom Company"

        elif (
            "friend" in text
            or "family" in text
            or "relative" in text
        ):

            caller_claim = "Friend/Family"

        result = analyze_call(
            "Unknown",
            caller_claim,
            asked_otp,
            asked_bank_details,
            demanded_payment,
            threatened_user,
            impersonated
        )

        return {
            "type": "CALL",
            "score": result.get(
                "score",
                0
            ),
            "risk_level": result.get(
                "risk_level",
                "LOWER RISK"
            ),
            "reasons": result.get(
                "reasons",
                []
            )
        }

    # ---------------------------------------------------------
    # UNKNOWN INPUT
    # ---------------------------------------------------------

    return {
        "type": "UNKNOWN",
        "score": 0,
        "risk_level": "LOWER RISK",
        "reasons": [
            "Unable to determine the type of input."
        ]
    }

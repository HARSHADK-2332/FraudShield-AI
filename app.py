# pyright: reportMissingImports=false, reportMissingTypeStubs=false, reportUnknownMemberType=false, reportUnknownArgumentType=false, reportUnknownVariableType=false, reportDeprecated=false

import streamlit as st
import joblib
import plotly.express as px

from urllib.parse import urlparse

from modules.url_detector import (
    extract_ml_features,
    analyze_url,
)

from modules.call_detector import (
    validate_phone_number,
    analyze_call,
)

from modules.message_detector import (
    analyze_message,
)

from modules.chatbot import (
    analyze_chat_input,
    detect_input_type,
    get_general_response,
    get_safety_advice,
)

from database import (
    create_database,
    save_scan,
    get_history,
    clear_history,
)


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="FraudShield AI",
    page_icon="🛡️",
    layout="centered",
)


# =========================================================
# LOAD ML MODEL
# =========================================================

try:

    ml_model = joblib.load(
        "ml/model.pkl"
    )

except FileNotFoundError:

    st.error(
        "❌ ML model not found. "
        "Please run: python ml/train_model.py"
    )

    st.stop()


# =========================================================
# CREATE / UPGRADE DATABASE
# =========================================================

create_database()


# =========================================================
# SESSION STATE
# =========================================================

if "page" not in st.session_state:

    st.session_state.page = "check"


if "chat_messages" not in st.session_state:

    st.session_state.chat_messages = []


# =========================================================
# LOAD THREAT DATABASE
# =========================================================

try:

    with open(
        "threat_domains.txt",
        "r"
    ) as file:

        threat_domains = {}

        for line in file:

            line = line.strip()

            if "|" in line:

                domain, threat_type = line.split(
                    "|",
                    1
                )

                threat_domains[
                    domain.lower()
                ] = threat_type.strip()

except FileNotFoundError:

    st.error(
        "❌ threat_domains.txt not found."
    )

    st.stop()


# =========================================================
# LOAD SAFE DATABASE
# =========================================================

try:

    with open(
        "safe_domains.txt",
        "r"
    ) as file:

        safe_domains = {
            line.strip().lower()
            for line in file
            if line.strip()
        }

except FileNotFoundError:

    st.error(
        "❌ safe_domains.txt not found."
    )

    st.stop()


# =========================================================
# CYBERPUNK UI THEME
# =========================================================

st.markdown(
    """
    <style>
    /* -----------------------------------------------------
       GLOBAL BACKGROUND + AMBIENT GLOW
       ----------------------------------------------------- */
    .stApp {
        background:
            radial-gradient(circle at 6% 8%, rgba(0, 229, 255, 0.24), transparent 22%),
            radial-gradient(circle at 94% 8%, rgba(255, 0, 153, 0.24), transparent 24%),
            radial-gradient(circle at 80% 72%, rgba(124, 58, 237, 0.22), transparent 24%),
            radial-gradient(circle at 18% 82%, rgba(255, 122, 0, 0.16), transparent 22%),
            radial-gradient(circle at 48% 36%, rgba(0, 245, 160, 0.10), transparent 25%),
            linear-gradient(125deg, #050516 0%, #09152f 28%, #19082d 58%, #071f25 100%);
        background-size: 160% 160%;
        animation: fs_bg_shift 18s ease-in-out infinite alternate;
        min-height: 100vh;
        overflow-x: hidden;
    }

    @keyframes fs_bg_shift {
        0% { background-position: 0% 0%; }
        50% { background-position: 100% 45%; }
        100% { background-position: 30% 100%; }
    }

    .stApp::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        z-index: 0;
        background:
            repeating-linear-gradient(
                180deg,
                rgba(255,255,255,0.018) 0px,
                rgba(255,255,255,0.018) 1px,
                transparent 1px,
                transparent 4px
            );
        animation: fs_scanlines 12s linear infinite;
        opacity: 0.18;
    }

    @keyframes fs_scanlines {
        from { transform: translateY(0); }
        to { transform: translateY(12px); }
    }

    /* -----------------------------------------------------
       FULL-SCREEN DANGER / FRAUD TATTOO WALL
       Pure CSS/HTML: survives deployment without extra files.
       ----------------------------------------------------- */
    .fs-tattoo-wall {
        position: fixed;
        inset: 0;
        z-index: 0;
        pointer-events: none;
        overflow: hidden;
        opacity: 0.22;
        transform: rotate(-7deg) scale(1.09);
        filter: drop-shadow(0 0 10px rgba(255, 0, 153, 0.06));
    }

    .fs-tattoo-row {
        position: absolute;
        left: -10%;
        width: 120%;
        display: flex;
        gap: 2.4rem;
        white-space: nowrap;
        font-family: Impact, Haettenschweiler, 'Arial Black', sans-serif;
        font-size: clamp(2rem, 4.7vw, 4.6rem);
        font-weight: 900;
        letter-spacing: 0.13em;
        text-transform: uppercase;
        opacity: 0.10;
        user-select: none;
        animation: fs_tattoo_drift 28s linear infinite;
    }

    .fs-tattoo-row span {
        -webkit-text-stroke: 1px rgba(255,255,255,0.11);
        text-shadow:
            0 0 12px rgba(255,255,255,0.06),
            0 0 30px rgba(0,229,255,0.05);
    }

    .fs-tattoo-row:nth-child(1) { top: 8%; color: #00e5ff; animation-duration: 31s; }
    .fs-tattoo-row:nth-child(2) { top: 24%; color: #ff3d81; animation-duration: 37s; animation-direction: reverse; opacity: 0.075; }
    .fs-tattoo-row:nth-child(3) { top: 42%; color: #ffb300; animation-duration: 34s; }
    .fs-tattoo-row:nth-child(4) { top: 60%; color: #a855f7; animation-duration: 41s; animation-direction: reverse; opacity: 0.08; }
    .fs-tattoo-row:nth-child(5) { top: 78%; color: #00f5a0; animation-duration: 35s; }
    .fs-tattoo-row:nth-child(6) { top: 94%; color: #ff4ecd; animation-duration: 39s; animation-direction: reverse; opacity: 0.07; }

    @keyframes fs_tattoo_drift {
        from { transform: translateX(-7%); }
        to { transform: translateX(7%); }
    }

    .fs-danger-stamp {
        position: absolute;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 180px;
        height: 180px;
        border: 5px double currentColor;
        border-radius: 50%;
        font-family: Impact, Haettenschweiler, 'Arial Black', sans-serif;
        font-size: 1.15rem;
        font-weight: 900;
        letter-spacing: 0.1em;
        text-align: center;
        line-height: 1.1;
        opacity: 0.08;
        transform: rotate(14deg);
        box-shadow: 0 0 30px currentColor, inset 0 0 28px currentColor;
        animation: fs_stamp_pulse 5s ease-in-out infinite;
    }

    .fs-danger-stamp::before {
        content: '⚠';
        position: absolute;
        top: 24px;
        font-size: 3.2rem;
    }

    .fs-danger-stamp.a { left: -35px; top: 18%; color: #ff3d81; }
    .fs-danger-stamp.b { right: -50px; top: 53%; color: #00e5ff; transform: rotate(-17deg); animation-delay: 1s; }
    .fs-danger-stamp.c { left: 42%; bottom: -65px; color: #ffb300; transform: rotate(-10deg); animation-delay: 2s; }

    @keyframes fs_stamp_pulse {
        0%, 100% { opacity: 0.055; }
        50% { opacity: 0.105; }
    }

    /* Extra diagonal hazard stripes behind the UI */
    .fs-hazard-strip {
        position: fixed;
        left: -8%;
        right: -8%;
        height: 22px;
        z-index: 0;
        pointer-events: none;
        opacity: 0.08;
        background: repeating-linear-gradient(
            135deg,
            #ffd400 0 14px,
            #111827 14px 28px
        );
        box-shadow: 0 0 20px rgba(255, 212, 0, 0.12);
        transform: rotate(-5deg);
    }

    .fs-hazard-strip.top { top: 13%; }
    .fs-hazard-strip.bottom { bottom: 12%; }

    /* -----------------------------------------------------
       MAIN CONTENT GLASS FEEL
       ----------------------------------------------------- */
    .block-container {
        position: relative;
        z-index: 3;
        padding-top: 2rem !important;
        padding-bottom: 7rem !important;
    }

    /* -----------------------------------------------------
       HERO HEADER
       ----------------------------------------------------- */
    .fs-hero {
        text-align: center;
        margin: 0 auto 1.4rem auto;
        padding: 1.35rem 1rem 1.2rem 1rem;
        border: 1px solid rgba(255,255,255,0.12);
        border-radius: 28px;
        background:
            linear-gradient(135deg, rgba(15,23,42,0.72), rgba(36,10,56,0.62));
        box-shadow:
            0 0 0 1px rgba(0,229,255,0.05) inset,
            0 0 45px rgba(0,229,255,0.08),
            0 18px 50px rgba(0,0,0,0.28);
        backdrop-filter: blur(16px);
        overflow: hidden;
        position: relative;
    }

    .fs-hero::before {
        content: "";
        position: absolute;
        inset: -35%;
        background: conic-gradient(
            from 0deg,
            rgba(0,229,255,0.08),
            transparent 20%,
            rgba(255,0,153,0.09),
            transparent 44%,
            rgba(255,179,0,0.08),
            transparent 68%,
            rgba(0,245,160,0.08),
            transparent 90%
        );
        animation: fs_hero_orbit 12s linear infinite;
        pointer-events: none;
    }

    @keyframes fs_hero_orbit {
        to { transform: rotate(360deg); }
    }

    .fs-hero::after {
        content: "";
        position: absolute;
        inset: -40%;
        background: conic-gradient(
            from 0deg,
            transparent,
            rgba(0,229,255,0.08),
            transparent 28%,
            rgba(255,0,153,0.08),
            transparent 52%,
            rgba(124,58,237,0.08),
            transparent 76%
        );
        animation: fs_spin 15s linear infinite;
        pointer-events: none;
    }

    @keyframes fs_spin {
        to { transform: rotate(360deg); }
    }

    .fs-hero-title {
        position: relative;
        z-index: 1;
        margin: 0;
        font-size: clamp(2.2rem, 6vw, 3.6rem);
        font-weight: 900;
        letter-spacing: 0.04em;
        background: linear-gradient(90deg, #00e5ff, #7c3aed, #ff0099, #00e5ff);
        background-size: 300% auto;
        -webkit-background-clip: text;
        background-clip: text;
        color: transparent;
        animation: fs_gradient 5s linear infinite;
        text-shadow: 0 0 35px rgba(0,229,255,0.12);
    }

    @keyframes fs_gradient {
        to { background-position: 300% center; }
    }

    .fs-hero-subtitle {
        position: relative;
        z-index: 1;
        margin: 0.35rem 0 0.7rem 0;
        color: rgba(255,255,255,0.78);
        font-size: 1rem;
        letter-spacing: 0.08em;
    }

    .fs-status-row {
        position: relative;
        z-index: 1;
        display: flex;
        justify-content: center;
        flex-wrap: wrap;
        gap: 0.55rem;
    }

    .fs-pill {
        display: inline-flex;
        align-items: center;
        gap: 0.35rem;
        padding: 0.4rem 0.75rem;
        border-radius: 999px;
        border: 1px solid rgba(255,255,255,0.12);
        background: rgba(255,255,255,0.06);
        color: rgba(255,255,255,0.9);
        font-size: 0.76rem;
        font-weight: 700;
        box-shadow: 0 0 18px rgba(124,58,237,0.09);
    }

    .fs-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #00f5a0;
        box-shadow: 0 0 12px #00f5a0;
        animation: fs_blink 1.2s ease-in-out infinite;
    }

    @keyframes fs_blink {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.5; transform: scale(0.72); }
    }

    /* -----------------------------------------------------
       ALL STREAMLIT BUTTONS
       ----------------------------------------------------- */
    div.stButton > button {
        border-radius: 16px !important;
        border: 1px solid rgba(255,255,255,0.13) !important;
        background:
            linear-gradient(135deg, rgba(18,25,55,0.95), rgba(44,13,67,0.94)) !important;
        color: #f8fbff !important;
        font-weight: 800 !important;
        letter-spacing: 0.02em !important;
        box-shadow:
            0 8px 24px rgba(0,0,0,0.22),
            0 0 18px rgba(124,58,237,0.10) !important;
        transition: all 0.22s ease !important;
    }

    div.stButton > button:hover {
        transform: translateY(-3px) scale(1.015);
        border-color: rgba(0,229,255,0.42) !important;
        background:
            linear-gradient(135deg, rgba(12,70,93,0.95), rgba(75,24,102,0.95)) !important;
        box-shadow:
            0 12px 30px rgba(0,0,0,0.28),
            0 0 24px rgba(0,229,255,0.22),
            0 0 34px rgba(255,0,153,0.10) !important;
    }

    div.stButton > button:active {
        transform: translateY(0) scale(0.985);
    }

    /* -----------------------------------------------------
       INPUTS / TEXT AREAS
       ----------------------------------------------------- */
    div[data-baseweb="input"] > div,
    div[data-baseweb="textarea"] > div {
        background: rgba(7,12,32,0.78) !important;
        border: 1px solid rgba(124,58,237,0.28) !important;
        border-radius: 15px !important;
        box-shadow: 0 0 20px rgba(124,58,237,0.06);
        transition: all 0.2s ease;
    }

    div[data-baseweb="input"] > div:focus-within,
    div[data-baseweb="textarea"] > div:focus-within {
        border-color: rgba(0,229,255,0.60) !important;
        box-shadow:
            0 0 0 1px rgba(0,229,255,0.12),
            0 0 24px rgba(0,229,255,0.14);
    }

    input, textarea {
        color: #f8fbff !important;
    }

    /* -----------------------------------------------------
       HIGH-CONTRAST NEON TEXT
       ----------------------------------------------------- */
    .main .block-container {
        background:
            linear-gradient(135deg, rgba(3, 8, 24, 0.72), rgba(20, 7, 38, 0.68));
        border: 1px solid rgba(0, 229, 255, 0.12);
        border-radius: 30px;
        box-shadow:
            0 0 0 1px rgba(255,255,255,0.025) inset,
            0 0 50px rgba(0,229,255,0.05),
            0 18px 60px rgba(0,0,0,0.25);
        backdrop-filter: blur(10px);
    }

    /* Main readable text */
    .stApp,
    .stApp p,
    .stApp li,
    .stApp span,
    .stApp small,
    .stApp label,
    .stApp [data-testid="stMarkdownContainer"],
    .stApp [data-testid="stMarkdownContainer"] p,
    .stApp [data-testid="stMarkdownContainer"] li {
        color: #eafcff !important;
    }

    /* Neon body text */
    .stApp p,
    .stApp li {
        text-shadow:
            0 0 5px rgba(0,229,255,0.10),
            0 0 12px rgba(124,58,237,0.07);
    }

    /* Widget labels */
    .stApp label,
    .stApp [data-testid="stWidgetLabel"],
    .stApp [data-testid="stWidgetLabel"] p {
        color: #dffbff !important;
        font-weight: 700 !important;
        text-shadow: 0 0 9px rgba(0,229,255,0.20);
    }

    /* Placeholder text: visible but softer */
    .stApp input::placeholder,
    .stApp textarea::placeholder {
        color: #9edce8 !important;
        opacity: 1 !important;
    }

    /* Input / select text */
    .stApp input,
    .stApp textarea,
    .stApp [data-baseweb="select"] *,
    .stApp [data-baseweb="input"] *,
    .stApp [data-baseweb="textarea"] * {
        color: #f4fdff !important;
        -webkit-text-fill-color: #f4fdff !important;
    }


    /* -----------------------------------------------------
       EXTRA INPUT VISIBILITY FIX
       Make typed text unmistakably visible across browsers
       and Streamlit/BaseWeb widgets.
       ----------------------------------------------------- */
    .stApp input,
    .stApp textarea,
    .stApp div[data-testid="stTextInput"] input,
    .stApp div[data-testid="stTextArea"] textarea,
    .stApp div[data-testid="stChatInput"] textarea {
        background: rgba(2, 7, 20, 0.96) !important;
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
        caret-color: #ffffff !important;
        text-shadow: 0 0 8px rgba(0, 229, 255, 0.16) !important;
    }

    .stApp input:focus,
    .stApp textarea:focus,
    .stApp div[data-testid="stTextInput"] input:focus,
    .stApp div[data-testid="stTextArea"] textarea:focus,
    .stApp div[data-testid="stChatInput"] textarea:focus {
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
        caret-color: #61f6ff !important;
        outline: none !important;
    }

    /* Selectbox selected value and dropdown text */
    .stApp [data-baseweb="select"] input,
    .stApp [data-baseweb="select"] [role="combobox"],
    .stApp [data-baseweb="select"] div,
    .stApp [data-baseweb="select"] span {
        color: #ffffff !important;
        -webkit-text-fill-color: #ffffff !important;
    }

    /* Streamlit chat input */
    .stApp [data-testid="stChatInput"] {
        background: rgba(2, 7, 20, 0.96) !important;
        border: 1px solid rgba(0, 229, 255, 0.34) !important;
        box-shadow: 0 0 20px rgba(0, 229, 255, 0.10) !important;
    }

    /* Checkbox / option text */
    .stApp [data-testid="stCheckbox"] label,
    .stApp [data-testid="stCheckbox"] label p,
    .stApp [data-testid="stRadio"] label,
    .stApp [data-testid="stRadio"] label p {
        color: #ecfbff !important;
    }

    /* Markdown links */
    .stApp a {
        color: #61f6ff !important;
        font-weight: 700 !important;
        text-shadow: 0 0 10px rgba(0,229,255,0.35);
    }

    /* Captions / helper text */
    .stApp [data-testid="stCaptionContainer"],
    .stApp [data-testid="stCaptionContainer"] p {
        color: #b8ecf5 !important;
    }

    /* Alerts need bright text against their colored glass */
    .stApp div[data-testid="stAlert"] * {
        color: #f8fdff !important;
        text-shadow: 0 0 8px rgba(255,255,255,0.10);
    }

    /* Metrics: bright label + value */
    .stApp [data-testid="stMetricLabel"],
    .stApp [data-testid="stMetricLabel"] *,
    .stApp [data-testid="stMetricValue"],
    .stApp [data-testid="stMetricValue"] * {
        color: #f6feff !important;
        -webkit-text-fill-color: #f6feff !important;
        text-shadow: 0 0 12px rgba(0,229,255,0.18);
    }

    /* -----------------------------------------------------
       HEADINGS
       ----------------------------------------------------- */
    h1, h2, h3 {
        color: #f8fbff !important;
        text-shadow:
            0 0 8px rgba(0,229,255,0.38),
            0 0 18px rgba(255,0,153,0.16);
    }

    h2, h3 {
        background: linear-gradient(90deg, #65f8ff, #d9b3ff, #ff79c8);
        -webkit-background-clip: text;
        background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    /* -----------------------------------------------------
       METRIC CARDS
       ----------------------------------------------------- */
    [data-testid="stMetric"] {
        padding: 0.8rem 0.9rem;
        border-radius: 18px;
        background: linear-gradient(135deg, rgba(15,23,42,0.80), rgba(44,13,67,0.62));
        border: 1px solid rgba(255,255,255,0.10);
        box-shadow: 0 0 24px rgba(124,58,237,0.08);
    }

    /* -----------------------------------------------------
       INFO / SUCCESS / WARNING / ERROR GLOW
       ----------------------------------------------------- */
    div[data-testid="stAlert"] {
        border-radius: 18px !important;
        backdrop-filter: blur(10px);
        box-shadow: 0 8px 26px rgba(0,0,0,0.15);
    }

    /* -----------------------------------------------------
       PROGRESS BAR
       ----------------------------------------------------- */
    div[data-testid="stProgressBar"] > div {
        background: rgba(255,255,255,0.08) !important;
        border-radius: 999px !important;
        padding: 2px;
    }

    div[data-testid="stProgressBar"] > div > div {
        background: linear-gradient(90deg, #00e5ff, #7c3aed, #ff0099) !important;
        border-radius: 999px !important;
        box-shadow: 0 0 18px rgba(0,229,255,0.35);
    }

    /* -----------------------------------------------------
       SELECTBOX / CHECKBOX
       ----------------------------------------------------- */
    div[data-baseweb="select"] > div {
        background: rgba(7,12,32,0.78) !important;
        border: 1px solid rgba(124,58,237,0.28) !important;
        border-radius: 15px !important;
    }

    /* -----------------------------------------------------
       DIVIDERS
       ----------------------------------------------------- */
    hr {
        border-color: rgba(0,229,255,0.12) !important;
        box-shadow: 0 0 12px rgba(0,229,255,0.06);
    }

    /* -----------------------------------------------------
       FLOATING AI ASSISTANT — BIG WHITE-LINE MIC + CLOUD
       ----------------------------------------------------- */
    div.st-key-ai_assistant {
        position: fixed;
        right: 28px;
        bottom: 28px;
        z-index: 1000001;
    }

    /* Cloud-style thought bubble: no arrow/tail */
    div.st-key-ai_assistant::before {
        content: "How can I help?";
        position: absolute;
        right: -10px;
        bottom: calc(100% + 22px);
        min-width: 190px;
        min-height: 66px;
        padding: 14px 22px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 48% 52% 50% 46% / 58% 52% 48% 42%;
        background: rgba(9, 16, 35, 0.96);
        color: #ffffff;
        border: 2px solid rgba(255,255,255,0.98);
        font-size: 16px;
        font-weight: 900;
        text-align: center;
        letter-spacing: 0.2px;
        white-space: nowrap;
        box-shadow:
            0 0 10px rgba(255,255,255,0.48),
            0 0 24px rgba(0,234,255,0.38),
            0 0 44px rgba(168,85,247,0.24),
            0 12px 28px rgba(0,0,0,0.30);
        text-shadow:
            0 0 7px rgba(255,255,255,0.85),
            0 0 16px rgba(0,234,255,0.55);
        animation: fraudshield_thought_float 2.8s ease-in-out infinite;
        pointer-events: none;
        z-index: 1000002;
    }

    /* Three rounded thinking puffs — deliberately no arrow */
    div.st-key-ai_assistant::after {
        content: "";
        position: absolute;
        right: 46px;
        bottom: calc(100% + 3px);
        width: 16px;
        height: 16px;
        border-radius: 50%;
        background: rgba(9, 16, 35, 0.96);
        border: 2px solid rgba(255,255,255,0.94);
        box-shadow:
            0 0 9px rgba(255,255,255,0.35),
            0 0 16px rgba(0,234,255,0.24),
            16px 7px 0 -3px rgba(9,16,35,0.96),
            16px 7px 0 -1px rgba(255,255,255,0.18),
            30px 17px 0 -5px rgba(9,16,35,0.96),
            30px 17px 0 -3px rgba(255,255,255,0.16);
        z-index: 1000001;
        pointer-events: none;
    }

    @keyframes fraudshield_thought_float {
        0%, 100% { transform: translateY(0); }
        50% { transform: translateY(-5px); }
    }

    /* Second tiny thinking dot via the button wrapper's background */
    div.st-key-ai_assistant {
        isolation: isolate;
    }

    div.st-key-ai_assistant button {
        width: 112px !important;
        height: 112px !important;
        min-width: 112px !important;
        min-height: 112px !important;
        max-width: 112px !important;
        max-height: 112px !important;
        padding: 0 !important;
        border-radius: 50% !important;
        font-size: 0 !important;
        line-height: 1 !important;
        color: transparent !important;
        background: rgba(7, 12, 28, 0.94) !important;
        border: 4px solid #ffffff !important;
        box-shadow:
            0 0 0 6px rgba(255,255,255,0.06),
            0 0 24px rgba(0,229,255,0.34),
            0 0 42px rgba(168,85,247,0.26),
            0 14px 34px rgba(0,0,0,0.38) !important;
        position: relative !important;
        overflow: hidden !important;
        animation: fraudshield_mic_pulse 2.4s ease-in-out infinite;
        transition: transform 0.2s ease, box-shadow 0.2s ease;
    }

    /* Large clean white-outline microphone drawn as an embedded SVG */
    div.st-key-ai_assistant button::before {
        content: "";
        position: absolute;
        inset: 19px;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Cg fill='none' stroke='white' stroke-width='6' stroke-linecap='round' stroke-linejoin='round'%3E%3Crect x='34' y='12' width='32' height='49' rx='16'/%3E%3Cpath d='M22 45v8c0 16 12 28 28 28s28-12 28-28v-8'/%3E%3Cpath d='M50 81v10'/%3E%3Cpath d='M36 91h28'/%3E%3C/g%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: center;
        background-size: contain;
        filter:
            drop-shadow(0 0 5px rgba(255,255,255,0.85))
            drop-shadow(0 0 16px rgba(0,234,255,0.70));
        pointer-events: none;
    }

    div.st-key-ai_assistant button:hover {
        transform: scale(1.10) !important;
        border-color: #ffffff !important;
        box-shadow:
            0 0 0 8px rgba(255,255,255,0.07),
            0 0 28px rgba(255,255,255,0.44),
            0 0 52px rgba(0,229,255,0.48),
            0 0 70px rgba(168,85,247,0.34),
            0 18px 42px rgba(0,0,0,0.40) !important;
    }

    div.st-key-ai_assistant:hover::before {
        border-color: #ffffff;
    }

    @keyframes fraudshield_mic_pulse {
        0%, 100% {
            box-shadow:
                0 0 0 6px rgba(255,255,255,0.06),
                0 0 24px rgba(0,229,255,0.34),
                0 0 42px rgba(168,85,247,0.26),
                0 14px 34px rgba(0,0,0,0.38);
        }
        50% {
            box-shadow:
                0 0 0 10px rgba(255,255,255,0.08),
                0 0 34px rgba(255,255,255,0.30),
                0 0 58px rgba(0,229,255,0.44),
                0 0 78px rgba(168,85,247,0.30),
                0 16px 38px rgba(0,0,0,0.40);
        }
    }

    @media (max-width: 640px) {
        .fs-tattoo-wall { opacity: 0.22; }
        .fs-danger-stamp { transform: scale(0.75) rotate(14deg); }
        .fs-danger-stamp.b { transform: scale(0.75) rotate(-17deg); }
        .fs-danger-stamp.c { transform: scale(0.75) rotate(-10deg); }

        .block-container {
            padding-left: 0.8rem !important;
            padding-right: 0.8rem !important;
        }

        div.st-key-ai_assistant {
            right: 14px;
            bottom: 14px;
        }

        div.st-key-ai_assistant::before {
            min-width: 154px;
            padding: 10px 15px;
            font-size: 14px;
            right: -2px;
        }

        div.st-key-ai_assistant::after {
            right: 30px;
            width: 14px;
            height: 14px;
        }

        div.st-key-ai_assistant button {
            width: 88px !important;
            height: 88px !important;
            min-width: 88px !important;
            min-height: 88px !important;
            max-width: 88px !important;
            max-height: 88px !important;
        }

        div.st-key-ai_assistant button::before {
            inset: 15px;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# DEPLOY-SAFE BACKGROUND ART
# =========================================================

st.markdown(
    """
    <div class="fs-tattoo-wall" aria-hidden="true">
        <div class="fs-tattoo-row">
            <span>⚠ DANGER</span><span>FRAUD</span><span>⚠ CAUTION</span><span>SCAM ALERT</span><span>PHISHING</span>
        </div>
        <div class="fs-tattoo-row">
            <span>🚨 FRAUD</span><span>DO NOT TRUST</span><span>⚠ DANGER</span><span>SCAM</span><span>ALERT</span>
        </div>
        <div class="fs-tattoo-row">
            <span>CAUTION</span><span>⚠ PHISHING</span><span>FRAUD SHIELD</span><span>🚨 WARNING</span><span>SCAM</span>
        </div>
        <div class="fs-tattoo-row">
            <span>⚠ DANGER</span><span>FRAUD</span><span>IDENTITY THEFT</span><span>CAUTION</span><span>PHISHING</span>
        </div>
        <div class="fs-tattoo-row">
            <span>SCAM ALERT</span><span>⚠ WARNING</span><span>FRAUD</span><span>DO NOT CLICK</span><span>CAUTION</span>
        </div>
        <div class="fs-tattoo-row">
            <span>⚠ DANGER</span><span>PHISHING</span><span>FRAUD</span><span>🚨 ALERT</span><span>SCAM</span>
        </div>

        <div class="fs-danger-stamp a">DANGER<br>ZONE</div>
        <div class="fs-danger-stamp b">FRAUD<br>ALERT</div>
        <div class="fs-danger-stamp c">CAUTION<br>PHISHING</div>
    </div>

    <div class="fs-hazard-strip top" aria-hidden="true"></div>
    <div class="fs-hazard-strip bottom" aria-hidden="true"></div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# APP TITLE
# =========================================================

st.markdown(
    """
    <div class="fs-hero">
        <div class="fs-hero-title">🛡️ FraudShield AI</div>
        <div class="fs-hero-subtitle">AI-POWERED FRAUD DETECTION SYSTEM</div>
        <div class="fs-status-row">
            <span class="fs-pill"><span class="fs-dot"></span> SCANNER ONLINE</span>
            <span class="fs-pill">🤖 AI ASSISTANT READY</span>
            <span class="fs-pill">🔐 DEFENSE MODE ACTIVE</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# NAVIGATION
# =========================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    if st.button(
        "🔍 Check URL",
        width="stretch"
    ):

        st.session_state.page = "check"


with col2:

    if st.button(
        "📞 Check Call",
        width="stretch"
    ):

        st.session_state.page = "call"


with col3:

    if st.button(
        "💬 Check Message",
        width="stretch"
    ):

        st.session_state.page = "message"


with col4:

    if st.button(
        "📋 History",
        width="stretch"
    ):

        st.session_state.page = "history"


# =========================================================
# FLOATING AI ASSISTANT
# =========================================================

if st.button(
    "MIC",
    key="ai_assistant",
    help="Talk to FraudShield AI",
):

    st.session_state.page = "chatbot"


# =========================================================
# =========================================================
# CHECK URL PAGE
# =========================================================
# =========================================================

if st.session_state.page == "check":

    st.subheader(
        "🔍 Check a Website"
    )

    url = st.text_input(
        "Enter a URL:",
        placeholder="https://example.com",
    )


    # =====================================================
    # SCAN URL BUTTON
    # =====================================================

    if st.button(
        "🚀 Scan URL",
        width="stretch"
    ):

        if not url:

            st.warning(
                "Please enter a URL."
            )

            st.stop()


        # =================================================
        # CLEAN URL
        # =================================================

        url = url.strip()


        # =================================================
        # BASIC URL VALIDATION
        # =================================================

        if not url.startswith(
            (
                "http://",
                "https://"
            )
        ):

            st.error(
                "❌ Please enter a valid URL starting "
                "with http:// or https://"
            )

            st.stop()


        # =================================================
        # PARSE URL
        # =================================================

        parsed_url = urlparse(url)

        domain = parsed_url.hostname


        if not domain:

            st.error(
                "❌ Invalid URL."
            )

            st.stop()


        domain = domain.lower()


        # =================================================
        # RUN RULE ENGINE
        # =================================================

        result = analyze_url(
            url,
            safe_domains,
            threat_domains,
        )


        if not result["valid"]:

            st.error(
                result["error"]
            )

            st.stop()


        # =================================================
        # EXTRACT RULE ENGINE VALUES
        # =================================================

        rule_score = result["rule_score"]

        critical_threat = result[
            "critical_threat"
        ]

        strong_threat = result[
            "strong_threat"
        ]

        reasons = list(
            result["reasons"]
        )


        # =================================================
        # ML FEATURE EXTRACTION
        # =================================================

        ml_features = extract_ml_features(
            url
        )


        # =================================================
        # ML PREDICTION
        # =================================================

        ml_prediction = ml_model.predict(
            [ml_features]
        )[0]


        # =================================================
        # ML CONFIDENCE
        # =================================================

        if hasattr(
            ml_model,
            "predict_proba"
        ):

            ml_probabilities = (
                ml_model.predict_proba(
                    [ml_features]
                )[0]
            )

            class_probabilities = dict(
                zip(
                    ml_model.classes_,
                    ml_probabilities
                )
            )

            ml_confidence = (
                class_probabilities.get(
                    ml_prediction,
                    0
                ) * 100
            )

        else:

            ml_confidence = 100.0


        # =================================================
        # ML RISK SCORE
        # =================================================

        if ml_prediction == 1:

            ml_score = ml_confidence

            ml_result = (
                "🚨 ML MODEL: PHISHING"
            )

        else:

            ml_score = (
                100 - ml_confidence
            )

            ml_result = (
                "✅ ML MODEL: LEGITIMATE"
            )


        # =================================================
        # ML RESULT DISPLAY
        # =================================================

        st.subheader(
            "🤖 AI/ML Prediction"
        )

        st.write(
            ml_result
        )

        st.metric(
            "🤖 Model Confidence",
            f"{ml_confidence:.2f}%"
        )


        # =================================================
        # SAFE DOMAIN STATUS
        # =================================================

        if domain in safe_domains:

            st.success(
                "✅ TRUSTED DOMAIN"
            )


        # =================================================
        # THREAT DATABASE STATUS
        # =================================================

        if domain in threat_domains:

            st.error(
                "🚨 KNOWN THREAT DETECTED"
            )

            st.write(
                "Threat Type:",
                threat_domains[domain]
            )


        # =================================================
        # URL ANALYSIS
        # =================================================

        st.subheader(
            "🔍 URL Analysis"
        )

        st.write(
            "🌐 Domain:",
            domain
        )

        st.write(
            "📏 URL Length:",
            result["url_length"]
        )

        st.write(
            "🔵 Number of dots:",
            result["dot_count"]
        )

        st.write(
            "➖ Number of hyphens:",
            result["hyphen_count"]
        )

        st.write(
            "🔢 Number of digits:",
            result["digit_count"]
        )

        st.write(
            "⚠️ Special characters:",
            result["special_count"]
        )


        # =================================================
        # FINAL SCORE CALCULATION
        # =================================================

        combined_score = int(
            (rule_score * 0.70)
            + (ml_score * 0.30)
        )


        # =================================================
        # DEFENSE-IN-DEPTH PROTECTION
        # =================================================

        if critical_threat:

            score = max(
                rule_score,
                combined_score,
                70,
            )

        elif strong_threat:

            score = max(
                rule_score,
                combined_score,
                60,
            )

        else:

            score = max(
                rule_score,
                combined_score,
            )


        # Keep score between 0 and 100

        score = min(
            int(score),
            100
        )


        # =================================================
        # ADD ML EXPLANATION
        # =================================================

        if ml_prediction == 1:

            reasons.append(
                "🤖 AI model detected "
                "phishing-like patterns "
                f"(confidence: "
                f"{ml_confidence:.2f}%)."
            )

        else:

            reasons.append(
                "🤖 AI model classified the URL "
                "as legitimate "
                f"(confidence: "
                f"{ml_confidence:.2f}%)."
            )


        # =================================================
        # FINAL RISK LEVEL
        # =================================================

        if critical_threat:

            risk_level = (
                "🔴 HIGH RISK"
            )

        elif strong_threat:

            risk_level = (
                "🔴 HIGH RISK"
            )

        elif score >= 60:

            risk_level = (
                "🔴 HIGH RISK"
            )

        elif score >= 30:

            risk_level = (
                "🟡 MEDIUM RISK"
            )

        else:

            risk_level = (
                "🟢 LOW RISK"
            )


        # =================================================
        # FINAL EXPLANATION
        # =================================================

        if score >= 60:

            explanation = (
                "🚨 This URL shows multiple "
                "suspicious patterns. "
                "Avoid opening it or entering "
                "personal information."
            )

        elif score >= 30:

            explanation = (
                "⚠️ This URL shows some "
                "suspicious patterns. "
                "Verify the website carefully "
                "before continuing."
            )

        else:

            explanation = (
                "✅ No major suspicious patterns "
                "were detected in this URL."
            )


        # =================================================
        # FINAL SAFETY RECOMMENDATION
        # =================================================

        if score >= 60:

            recommendation = (
                "🚫 Do not open this link. "
                "Do not enter personal or "
                "banking information."
            )

        elif score >= 30:

            recommendation = (
                "⚠️ Be careful. Verify the website "
                "through an official source before "
                "entering personal information."
            )

        else:

            recommendation = (
                "✅ No major suspicious patterns "
                "detected. Still verify the website "
                "before sharing sensitive information."
            )


        # =================================================
        # SCORE BREAKDOWN
        # =================================================

        st.subheader(
            "📊 Detection Score Breakdown"
        )

        breakdown_col1, breakdown_col2, breakdown_col3 = (
            st.columns(3)
        )


        with breakdown_col1:

            st.metric(
                "🧠 Rule Engine",
                f"{rule_score}/100"
            )


        with breakdown_col2:

            st.metric(
                "🤖 ML Risk Score",
                f"{ml_score:.1f}/100"
            )


        with breakdown_col3:

            st.metric(
                "🎯 Final Score",
                f"{score}/100"
            )


        # =================================================
        # DETECTION METHOD STATUS
        # =================================================

        if (
            strong_threat
            or critical_threat
        ):

            st.warning(
                "🛡️ Rule Engine protection is active. "
                "A strong security signal cannot be "
                "downgraded by the ML model."
            )


        # =================================================
        # WHY THIS RESULT?
        # =================================================

        st.subheader(
            "💡 Why This Result?"
        )

        st.info(
            explanation
        )


        # =================================================
        # SAFETY RECOMMENDATION
        # =================================================

        st.subheader(
            "🛡️ Safety Recommendation"
        )

        st.info(
            recommendation
        )


        # =================================================
        # FINAL RESULT
        # =================================================

        st.subheader(
            "🎯 Final Result"
        )

        st.write(
            "Risk Level:",
            risk_level
        )

        st.write(
            "Risk Score:",
            score
        )

        st.progress(
            score / 100
        )


        if score < 30:

            st.success(
                risk_level
            )

        elif score < 60:

            st.warning(
                risk_level
            )

        else:

            st.error(
                risk_level
            )


        # =================================================
        # DETECTION DETAILS
        # =================================================

        st.subheader(
            "🔎 Detection Details"
        )

        if reasons:

            for reason in reasons:

                st.write(
                    reason
                )

        else:

            st.write(
                "✅ No suspicious patterns detected."
            )


        # =================================================
        # SAVE URL RESULT
        # =================================================

        save_scan(
            url,
            score,
            risk_level,
            "URL"
        )

        st.success(
            "✅ URL scan saved to history!"
        )


# =========================================================
# =========================================================
# CHECK CALL PAGE
# =========================================================
# =========================================================

elif st.session_state.page == "call":

    st.subheader(
        "📞 Fraud Call Analysis"
    )

    st.write(
        "Enter the caller's information and "
        "tell FraudShield what happened during the call."
    )


    # =====================================================
    # CALLER NUMBER
    # =====================================================

    phone_number = st.text_input(
        "📞 Caller Number",
        placeholder="+91 9876543210",
    )


    # =====================================================
    # CALLER CLAIM
    # =====================================================

    caller_claim = st.selectbox(
        "🗣️ What did the caller claim?",
        [
            "Unknown",
            "Bank",
            "Police/Government",
            "Delivery Company",
            "Job/Recruitment",
            "Telecom Company",
            "Friend/Family",
            "Other",
        ],
    )


    st.write(
        "### 🚨 What happened during the call?"
    )


    # =====================================================
    # CALL BEHAVIOR
    # =====================================================

    asked_otp = st.checkbox(
        "🔐 Did the caller ask for an OTP?"
    )

    asked_bank_details = st.checkbox(
        "💳 Did the caller ask for bank/card details?"
    )

    demanded_payment = st.checkbox(
        "💰 Did the caller demand immediate payment?"
    )

    threatened_user = st.checkbox(
        "⚠️ Did the caller threaten or pressure you?"
    )

    impersonated = st.checkbox(
        "🎭 Did the caller impersonate a bank, "
        "police officer, government official, "
        "company, or another person?"
    )


    # =====================================================
    # ANALYZE CALL BUTTON
    # =====================================================

    if st.button(
        "🔍 Analyze Call",
        width="stretch"
    ):

        # =================================================
        # PHONE NUMBER VALIDATION
        # =================================================

        if not phone_number.strip():

            st.warning(
                "Please enter the caller's phone number."
            )

            st.stop()


        if not validate_phone_number(
            phone_number
        ):

            st.error(
                "❌ Please enter a valid phone number."
            )

            st.stop()


        # =================================================
        # ANALYZE CALL
        # =================================================

        call_result = analyze_call(
            phone_number,
            caller_claim,
            asked_otp,
            asked_bank_details,
            demanded_payment,
            threatened_user,
            impersonated,
        )


        call_score = call_result["score"]

        call_risk = call_result[
            "risk_level"
        ]

        call_reasons = call_result[
            "reasons"
        ]


        # =================================================
        # RISK LEVEL DISPLAY
        # =================================================

        st.subheader(
            "🎯 Call Risk Assessment"
        )


        if call_risk == "HIGH":

            st.error(
                "🔴 HIGH RISK"
            )

        elif call_risk == "SUSPICIOUS":

            st.warning(
                "🟡 SUSPICIOUS"
            )

        else:

            st.success(
                "🟢 LOWER RISK"
            )


        # =================================================
        # SCORE
        # =================================================

        st.metric(
            "📊 Fraud Risk Score",
            f"{call_score}/100"
        )

        st.progress(
            call_score / 100
        )


        # =================================================
        # WHY THIS RESULT?
        # =================================================

        st.subheader(
            "💡 Why This Result?"
        )


        if call_reasons:

            for reason in call_reasons:

                st.write(
                    "• " + reason
                )

        else:

            st.write(
                "✅ No major fraud indicators "
                "were identified from the information provided."
            )


        # =================================================
        # SAFETY RECOMMENDATION
        # =================================================

        st.subheader(
            "🛡️ Safety Recommendation"
        )


        if call_score >= 60:

            st.error(
                "🚫 Treat this call as high risk. "
                "Do not share OTPs, passwords, "
                "banking/card information, or send money. "
                "If the caller claims to represent an "
                "organization, verify them using an "
                "official contact method."
            )

        elif call_score >= 30:

            st.warning(
                "⚠️ Be cautious with this caller. "
                "Do not share sensitive information "
                "until you independently verify "
                "the caller's identity."
            )

        else:

            st.info(
                "ℹ️ No major warning signs were identified "
                "from the information provided. "
                "This does not guarantee that the caller "
                "is legitimate."
            )


        # =================================================
        # CALLER INFORMATION
        # =================================================

        st.subheader(
            "📞 Call Information"
        )

        st.write(
            "Caller Number:",
            phone_number
        )

        st.write(
            "Caller Claim:",
            caller_claim
        )


        # =================================================
        # DETECTION DETAILS
        # =================================================

        st.subheader(
            "🔎 Detection Details"
        )

        if call_reasons:

            for reason in call_reasons:

                st.write(
                    reason
                )

        else:

            st.write(
                "✅ No suspicious call behavior detected."
            )


        # =================================================
        # NORMALIZE CALL RISK FOR DATABASE
        # =================================================

        if call_risk == "HIGH":

            database_risk = "🔴 HIGH RISK"

        elif call_risk == "SUSPICIOUS":

            database_risk = "🟡 MEDIUM RISK"

        else:

            database_risk = "🟢 LOW RISK"


        # =================================================
        # SAVE CALL RESULT
        # =================================================

        save_scan(
            phone_number,
            call_score,
            database_risk,
            "CALL"
        )

        st.success(
            "✅ Call analysis saved to history!"
        )


# =========================================================
# =========================================================
# CHECK MESSAGE PAGE
# =========================================================
# =========================================================

elif st.session_state.page == "message":

    st.subheader(
        "💬 Fraud Message Analysis"
    )

    st.write(
        "Paste a suspicious SMS, email, or chat message "
        "and FraudShield will check for common fraud indicators."
    )


    # =====================================================
    # MESSAGE INPUT
    # =====================================================

    message = st.text_area(
        "📩 Enter the message:",
        placeholder=(
            "Example: "
            "URGENT! Your account will be blocked. "
            "Click the link to verify your account."
        ),
        height=180,
    )


    # =====================================================
    # ANALYZE MESSAGE BUTTON
    # =====================================================

    if st.button(
        "🔍 Analyze Message",
        width="stretch"
    ):

        if not message.strip():

            st.warning(
                "Please enter a message."
            )

            st.stop()


        # =================================================
        # ANALYZE MESSAGE
        # =================================================

        message_result = analyze_message(
            message
        )


        message_score = message_result[
            "score"
        ]

        message_risk = message_result[
            "risk_level"
        ]

        message_reasons = message_result[
            "reasons"
        ]


        # =================================================
        # RISK ASSESSMENT
        # =================================================

        st.subheader(
            "🎯 Message Risk Assessment"
        )


        if message_risk == "HIGH":

            st.error(
                "🔴 HIGH RISK"
            )

        elif message_risk == "SUSPICIOUS":

            st.warning(
                "🟡 SUSPICIOUS"
            )

        else:

            st.success(
                "🟢 LOWER RISK"
            )


        # =================================================
        # SCORE
        # =================================================

        st.metric(
            "📊 Fraud Risk Score",
            f"{message_score}/100"
        )

        st.progress(
            message_score / 100
        )


        # =================================================
        # WHY THIS RESULT?
        # =================================================

        st.subheader(
            "💡 Why This Result?"
        )


        if message_reasons:

            for reason in message_reasons:

                st.write(
                    "• " + reason
                )

        else:

            st.write(
                "✅ No major fraud indicators "
                "were identified from the information provided."
            )


        # =================================================
        # SAFETY RECOMMENDATION
        # =================================================

        st.subheader(
            "🛡️ Safety Recommendation"
        )


        if message_score >= 60:

            st.error(
                "🚫 This message contains multiple "
                "fraud indicators. Do not click "
                "links, share OTPs or passwords, "
                "or send money based only on this message. "
                "Verify the claim through an official source."
            )

        elif message_score >= 30:

            st.warning(
                "⚠️ This message contains some "
                "suspicious indicators. Avoid sharing "
                "sensitive information until you "
                "independently verify the message."
            )

        else:

            st.info(
                "ℹ️ No major fraud indicators were "
                "identified from the message. "
                "This does not guarantee that the message "
                "is legitimate."
            )


        # =================================================
        # MESSAGE INFORMATION
        # =================================================

        st.subheader(
            "📩 Message Information"
        )

        st.write(
            "Message Length:",
            len(message)
        )

        st.write(
            "Words:",
            len(message.split())
        )


        # =================================================
        # DETECTION DETAILS
        # =================================================

        st.subheader(
            "🔎 Detection Details"
        )

        if message_reasons:

            for reason in message_reasons:

                st.write(
                    reason
                )

        else:

            st.write(
                "✅ No suspicious message behavior detected."
            )


        # =================================================
        # NORMALIZE MESSAGE RISK FOR DATABASE
        # =================================================

        if message_risk == "HIGH":

            database_risk = "🔴 HIGH RISK"

        elif message_risk == "SUSPICIOUS":

            database_risk = "🟡 MEDIUM RISK"

        else:

            database_risk = "🟢 LOW RISK"


        # =================================================
        # SAVE MESSAGE RESULT
        # =================================================

        save_scan(
            message,
            message_score,
            database_risk,
            "MESSAGE"
        )

        st.success(
            "✅ Message analysis saved to history!"
        )


# =========================================================
# =========================================================
# CHATBOT PAGE
# =========================================================
# =========================================================

elif st.session_state.page == "chatbot":

    st.subheader(
        "🤖 FraudShield AI Chatbot"
    )

    st.write(
        "Describe a suspicious URL, call, message, "
        "or ask a general fraud-safety question."
    )

    st.info(
        "🛡️ Never enter a real OTP, password, PIN, CVV, "
        "or other sensitive information."
    )

    # ---------------------------------------------------------
    # DISPLAY PREVIOUS CHAT
    # ---------------------------------------------------------

    for chat in st.session_state.chat_messages:

        with st.chat_message(chat["role"]):

            st.markdown(chat["content"])

    # ---------------------------------------------------------
    # CHAT INPUT
    # ---------------------------------------------------------

    user_input = st.chat_input(
        "Paste a URL, message, or describe a suspicious call..."
    )

    if user_input:

        user_input = user_input.strip()

        if user_input:

            st.session_state.chat_messages.append(
                {
                    "role": "user",
                    "content": user_input,
                }
            )

            with st.chat_message("user"):

                st.markdown(user_input)

            # -------------------------------------------------
            # DETERMINE INPUT TYPE
            # -------------------------------------------------

            input_type = detect_input_type(
                user_input
            )

            response_parts = []

            # General questions should receive the chatbot
            # guidance instead of being scored as fraud messages.
            general_question = any(
                phrase in user_input.lower()
                for phrase in [
                    "how do i use",
                    "how to use",
                    "how can i use",
                    "what is fraudshield",
                    "what does fraudshield do",
                    "how does this work",
                    "what should i do",
                    "is this safe",
                    "what is phishing",
                    "what are phishing links",
                ]
            )

            if (
                general_question
                and input_type != "url"
                and input_type != "call"
            ):

                response_parts.append(
                    get_general_response(
                        user_input
                    )
                )

                analysis = {
                    "type": "GENERAL",
                    "score": 0,
                    "risk_level": "LOWER RISK",
                    "reasons": [],
                }

            else:

                # -------------------------------------------------
                # DETECTOR ANALYSIS
                # -------------------------------------------------

                analysis = analyze_chat_input(
                    user_input,
                    safe_domains,
                    threat_domains,
                )

            # -------------------------------------------------
            # KEEP CHATBOT URL SCORE CONSISTENT WITH MAIN URL
            # DETECTOR
            # -------------------------------------------------
            # The chatbot detector gives the rule-engine result.
            # For URLs, recalculate the exact same Rule + ML
            # final score used on the main Check URL page.

            if analysis["type"] == "URL":

                chatbot_url_result = analyze_url(
                    user_input,
                    safe_domains,
                    threat_domains,
                )

                if chatbot_url_result.get("valid", False):

                    chatbot_rule_score = chatbot_url_result[
                        "rule_score"
                    ]

                    chatbot_features = extract_ml_features(
                        user_input
                    )

                    chatbot_prediction = ml_model.predict(
                        [chatbot_features]
                    )[0]

                    if hasattr(
                        ml_model,
                        "predict_proba"
                    ):

                        chatbot_probabilities = ml_model.predict_proba(
                            [chatbot_features]
                        )[0]

                        chatbot_class_probabilities = dict(
                            zip(
                                ml_model.classes_,
                                chatbot_probabilities,
                            )
                        )

                        chatbot_confidence = (
                            chatbot_class_probabilities.get(
                                chatbot_prediction,
                                0,
                            ) * 100
                        )

                    else:

                        chatbot_confidence = 100.0

                    if chatbot_prediction == 1:

                        chatbot_ml_score = chatbot_confidence

                        chatbot_ml_reason = (
                            "🤖 AI model detected phishing-like "
                            "patterns "
                            f"(confidence: "
                            f"{chatbot_confidence:.2f}%)."
                        )

                    else:

                        chatbot_ml_score = (
                            100 - chatbot_confidence
                        )

                        chatbot_ml_reason = (
                            "🤖 AI model classified the URL as "
                            "legitimate "
                            f"(confidence: "
                            f"{chatbot_confidence:.2f}%)."
                        )

                    chatbot_combined_score = int(
                        (chatbot_rule_score * 0.70)
                        + (chatbot_ml_score * 0.30)
                    )

                    chatbot_critical = chatbot_url_result[
                        "critical_threat"
                    ]

                    chatbot_strong = chatbot_url_result[
                        "strong_threat"
                    ]

                    if chatbot_critical:

                        chatbot_score = max(
                            chatbot_rule_score,
                            chatbot_combined_score,
                            70,
                        )

                    elif chatbot_strong:

                        chatbot_score = max(
                            chatbot_rule_score,
                            chatbot_combined_score,
                            60,
                        )

                    else:

                        chatbot_score = max(
                            chatbot_rule_score,
                            chatbot_combined_score,
                        )

                    chatbot_score = min(
                        int(chatbot_score),
                        100,
                    )

                    if chatbot_critical or chatbot_strong or chatbot_score >= 60:

                        chatbot_risk_level = "🔴 HIGH RISK"

                    elif chatbot_score >= 30:

                        chatbot_risk_level = "🟡 MEDIUM RISK"

                    else:

                        chatbot_risk_level = "🟢 LOW RISK"

                    chatbot_reasons = list(
                        chatbot_url_result.get(
                            "reasons",
                            [],
                        )
                    )

                    chatbot_reasons.append(
                        chatbot_ml_reason
                    )

                    analysis = {
                        "type": "URL",
                        "score": chatbot_score,
                        "risk_level": chatbot_risk_level,
                        "reasons": chatbot_reasons,
                    }

                else:

                    analysis = {
                        "type": "URL",
                        "score": analysis.get("score", 0),
                        "risk_level": analysis.get(
                            "risk_level",
                            "🟢 LOW RISK",
                        ),
                        "reasons": analysis.get(
                            "reasons",
                            [],
                        ),
                    }

            # If the input was recognized as a URL, call the
            # existing URL detector and show its real result.
            if analysis["type"] == "URL":

                if analysis["risk_level"] != "LOWER RISK":

                    response_parts.append(
                        f"### 🔗 URL Analysis\n\n"
                        f"**Risk Score:** "
                        f"{analysis['score']}/100\n\n"
                        f"**Risk Level:** "
                        f"{analysis['risk_level']}"
                    )

                    if analysis["reasons"]:

                        response_parts.append(
                            "**Why:**\n\n"
                            + "\n".join(
                                f"- {reason}"
                                for reason in analysis["reasons"]
                            )
                        )

                    url_risk = analysis["risk_level"]

                    if "HIGH" in url_risk:

                        response_parts.append(
                            get_safety_advice("HIGH")
                        )

                    elif "MEDIUM" in url_risk:

                        response_parts.append(
                            get_safety_advice("SUSPICIOUS")
                        )

                    else:

                        response_parts.append(
                            get_safety_advice("LOWER RISK")
                        )

                else:

                    response_parts.append(
                        f"### 🔗 URL Analysis\n\n"
                        f"**Risk Score:** "
                        f"{analysis['score']}/100\n\n"
                        f"**Risk Level:** "
                        f"{analysis['risk_level']}"
                    )

                    if analysis["reasons"]:

                        response_parts.append(
                            "**Why:**\n\n"
                            + "\n".join(
                                f"- {reason}"
                                for reason in analysis["reasons"]
                            )
                        )

                    response_parts.append(
                        get_safety_advice("LOWER RISK")
                    )

            # -------------------------------------------------
            # MESSAGE ANALYSIS
            # -------------------------------------------------

            elif analysis["type"] == "MESSAGE":

                response_parts.append(
                    f"### 💬 Message Analysis\n\n"
                    f"**Risk Score:** "
                    f"{analysis['score']}/100\n\n"
                    f"**Risk Level:** "
                    f"{analysis['risk_level']}"
                )

                if analysis["reasons"]:

                    response_parts.append(
                        "**Why:**\n\n"
                        + "\n".join(
                            f"- {reason}"
                            for reason in analysis["reasons"]
                        )
                    )

                response_parts.append(
                    get_safety_advice(
                        analysis["risk_level"]
                    )
                )

            # -------------------------------------------------
            # CALL ANALYSIS
            # -------------------------------------------------

            elif analysis["type"] == "CALL":

                response_parts.append(
                    f"### 📞 Call Analysis\n\n"
                    f"**Risk Score:** "
                    f"{analysis['score']}/100\n\n"
                    f"**Risk Level:** "
                    f"{analysis['risk_level']}"
                )

                if analysis["reasons"]:

                    response_parts.append(
                        "**Why:**\n\n"
                        + "\n".join(
                            f"- {reason}"
                            for reason in analysis["reasons"]
                        )
                    )

                response_parts.append(
                    get_safety_advice(
                        analysis["risk_level"]
                    )
                )

            # -------------------------------------------------
            # GENERAL RESPONSE
            # -------------------------------------------------

            else:

                response_parts.append(
                    get_general_response(user_input)
                )

            assistant_response = "\n\n".join(
                response_parts
            )

            st.session_state.chat_messages.append(
                {
                    "role": "assistant",
                    "content": assistant_response,
                }
            )

            with st.chat_message("assistant"):

                st.markdown(
                    assistant_response
                )

    # ---------------------------------------------------------
    # CLEAR CHAT
    # ---------------------------------------------------------

    if st.session_state.chat_messages:

        if st.button(
            "🗑️ Clear Chat",
            width="stretch"
        ):

            st.session_state.chat_messages = []

            st.rerun()


# =========================================================
# =========================================================
# HISTORY PAGE
# =========================================================
# =========================================================

elif st.session_state.page == "history":

    st.subheader(
        "📋 FraudShield History"
    )

    history = get_history()

    # =====================================================
    # IF HISTORY EXISTS
    # =====================================================

    if history:

        total_scans = len(history)

        # =================================================
        # RISK COUNTS
        # =================================================

        # Database row order:
        # id, input, score, risk, detection_type, timestamp

        high_risk = sum(
            1
            for scan in history
            if "HIGH RISK" in str(scan[3])
        )

        medium_risk = sum(
            1
            for scan in history
            if (
                "MEDIUM RISK" in str(scan[3])
                or "SUSPICIOUS" in str(scan[3])
            )
        )

        low_risk = sum(
            1
            for scan in history
            if (
                "LOW RISK" in str(scan[3])
                or "LOWER RISK" in str(scan[3])
            )
        )

        # =================================================
        # SUMMARY
        # =================================================

        st.subheader(
            "📊 Scan Summary"
        )

        col1, col2, col3, col4 = st.columns(4)

        with col1:

            st.metric(
                "Total Scans",
                total_scans
            )

        with col2:

            st.metric(
                "🔴 High Risk",
                high_risk
            )

        with col3:

            st.metric(
                "🟡 Medium Risk",
                medium_risk
            )

        with col4:

            st.metric(
                "🟢 Low Risk",
                low_risk
            )

        # =================================================
        # CHART
        # =================================================

        chart_data = {
            "Risk Level": [
                "High Risk",
                "Medium Risk",
                "Low Risk",
            ],
            "Count": [
                high_risk,
                medium_risk,
                low_risk,
            ],
        }

        fig = px.bar(
            chart_data,
            x="Risk Level",
            y="Count",
            title="Fraud Scan Risk Distribution",
        )

        st.plotly_chart(
            fig,
            width="stretch"
        )

        # =================================================
        # HISTORY SEARCH
        # =================================================

        search_text = st.text_input(
            "🔎 Search History",
            placeholder="Search URL, phone number, message, or type..."
        )

        # =================================================
        # HISTORY TABLE
        # =================================================

        st.subheader(
            "🗂️ Previous Scans"
        )

        displayed_count = 0

        for scan in history:

            scan_text = " ".join(
                str(value)
                for value in scan
            ).lower()

            if (
                search_text.strip()
                and search_text.lower() not in scan_text
            ):

                continue

            displayed_count += 1

            with st.container(border=True):

                # Database rows normally contain:
                # id, content, risk, type, timestamp.
                # Display safely even if an older database
                # contains a slightly different row shape.

                st.write(
                    "🆔 Scan ID:",
                    scan[0] if len(scan) > 0 else "N/A"
                )

                # Database row order:
                # id, input, score, risk, detection_type, timestamp

                detection_type = (
                    str(scan[4]).upper()
                    if len(scan) > 4
                    else "UNKNOWN"
                )

                detection_label = {
                    "URL": "🔗 URL",
                    "CALL": "📞 CALL",
                    "MESSAGE": "💬 MESSAGE",
                }.get(
                    detection_type,
                    f"🔎 {detection_type}"
                )

                st.write(
                    "🛡️ Detection:",
                    detection_label
                )

                st.write(
                    "📌 Input:",
                    scan[1] if len(scan) > 1 else "N/A"
                )

                st.write(
                    "📊 Score:",
                    f"{scan[2]}/100"
                    if len(scan) > 2
                    else "N/A"
                )

                st.write(
                    "🎯 Risk:",
                    scan[3] if len(scan) > 3 else "N/A"
                )

                if len(scan) > 5:

                    st.write(
                        "🕒 Time:",
                        scan[5]
                    )


        if displayed_count == 0:

            st.info(
                "No matching scans found."
            )

        # =================================================
        # CLEAR HISTORY
        # =================================================

        st.divider()

        if st.button(
            "🗑️ Clear Scan History",
            width="stretch"
        ):

            clear_history()

            st.success(
                "✅ Scan history cleared."
            )

            st.rerun()

    else:

        st.info(
            "📭 No scan history yet. "
            "Analyze a URL, call, or message to create history."
        )

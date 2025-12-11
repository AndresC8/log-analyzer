import streamlit as st

import streamlit as st

TEXT = {
    "es": {
        "header_title": "🛡️ SOC Analyzer Dashboard",
        "header_subtitle": "Motor de detección, análisis de logs y visualización de anomalías.",

        "sidebar_config": "⚙️ Configuración",
        "sidebar_upload_text": "Sube un CSV:",
        "sidebar_upload_label": "SELECCIONAR ARCHIVO",
        "sidebar_upload_help": "Carga los logs",
        "sidebar_footer": "SOC Analyzer V2",

        "no_file_info": "Sube un archivo CSV de logs en la barra lateral para comenzar el análisis.",
        "log_loaded_tab_title": "📄 Log cargado",
        "log_loaded_info": "Carga un CSV para visualizar los logs",
    },

    "en": {
        "header_title": "🛡️ SOC Analyzer Dashboard",
        "header_subtitle": "Detection engine, log analysis and anomaly visualization.",

        "sidebar_config": "⚙️ Settings",
        "sidebar_upload_text": "Upload a CSV:",
        "sidebar_upload_label": "SELECT FILE",
        "sidebar_upload_help": "Upload log file",
        "sidebar_footer": "SOC Analyzer V2",

        "no_file_info": "Upload a CSV log file from the sidebar to start the analysis.",
        "log_loaded_tab_title": "📄 Loaded Log",
        "log_loaded_info": "Upload a CSV to display the logs",
    }
}

def t(key: str) -> str:
    lang = st.session_state.get("lang", "es")
    return TEXT.get(lang, TEXT["es"]).get(key, key)
import streamlit as st
import pandas as pd
from analyzer import detections
import matplotlib.pyplot as plt
import seaborn as sns

st.set_page_config(
    page_title="SOC Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def render_sidebar():
    with st.sidebar:
        st.header("⚙️ Configuración")
        st.markdown("Sube un csv: ")

        uploaded_file = st.file_uploader(
            "SELECCIONAR ARCHIVO",
            type=["csv"],
            help="Carga los logs"
        )

        st.markdown("---")
        st.subheader("Parámetros de detección")

        bruteforce_threshold = st.slider(
            "Intentos fallidos mínimos (brute_force)",
            min_value = 2,
            max_value = 20,
            value = 5, 
        )

        portscan_threshold = st.slider(
            "Port probes mínimos (portscan)",
            min_value= 2,
            max_value=20,
            value=5,
        )

    return uploaded_file, bruteforce_threshold, portscan_threshold


def load_logs(uploaded_file):
    df_logs = None

    if uploaded_file is None:
        return None
    df = pd.read_csv(uploaded_file)
    return df

def render_header():
    st.title("🛡️ SOC Analyzer Dashboard")
    st.markdown("### Visualización interactiva de logs y detecciones SOC")
    st.divider()

def render_tabs(df_logs, results):
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
        [
            "📄 Log cargado",
            "🔐 Brute Force",
            "🟢 Successful Brute Force",
            "📊 Portscan",
            "⏰ Off-hours Logins",
            "🔁 Password Spraying",
            "🤖 SOC Copilot"
        ]
    )

    with tab1:
        st.subheader("📄 Log cargado")
        if df_logs is None:
            st.info("Carga un csv en la sidebar para visualizar los logs")
        else:
            st.write(f"Filas: **{df_logs.shape[0]}**, Columnas **{df_logs.shape[1]}**")
            st.dataframe(df_logs)
    with tab2:
        st.subheader("🔐 Brute Force")

        brute_df = results.get("brute_force")

        if brute_df.empty:
            st.success("No se detectaron ataques de fuerza bruta")
        else:
            st.write(f"IPs sospechosas detectadas: {brute_df.shape[0]}")
            st.dataframe(brute_df)
            st.markdown("IPs sospechosas por intentos fallidos")
            brute_df_sorted = brute_df.sort_values(by="failures", ascending=False)
            fig, ax = plt.subplots(figsize=(8, 4))
            sns.barplot(
                data=brute_df_sorted,
                x="source_ip",
                y="failures",
                ax=ax
            )
            ax.set_label("IP origen")
            ax.set_label("Intentos fallidos")
            ax.set_label("IPs con más intentos fallidos")
            plt.xticks(rotation=45, ha="right")
            st.pyplot(fig)

    with tab3:
        st.subheader("🟢 Successful Brute Force")
        st.write("Aquí irá esta detección.")

    with tab4:
        st.subheader("📊 Portscan")
        portscan_df = results.get("port_scan")
        if portscan_df.empty:
            st.success("No se detectaron portscan")
        else:
            st.write(f"IPs sospechosas: {portscan_df.shape[0]}")
            st.dataframe(portscan_df)
            st.markdown("IPs sospechosas por escaneo de puertos")

            portscan_df_sorted = portscan_df.sort_values(by="portscan", ascending=False)
            fig, ax = plt.subplots(figsize=(8, 4))
            sns.barplot(
                data = portscan_df_sorted,
                x="source_ip",
                y="portscan",
                ax=ax,
            )
            ax.set_label("IP origen")
            ax.set_label("Escaneos")
            ax.set_label("IPs con mas puertos escaneados")
            plt.xticks(rotation=45, ha="right")
            st.pyplot(fig)

    with tab5:
        st.subheader("⏰ Off-hours Logins")
        st.write("Aquí se visualizarán los inicios de sesión fuera de horario.")

    with tab6:
        st.subheader("🔁 Password Spraying")
        st.write("Aquí estará la detección Password Spraying.")

    with tab7:
        st.subheader("🤖 SOC Copilot IA")
        st.write("Aquí más adelante enviaremos hallazgos a una IA.")

def run_detections(
        df_logs, 
        bruteforce_threshold,
        portscan_threshold,
):
    if df_logs is None:
        return {}
    
    results = {}
    brute_force_df = detections.detect_bruteforce(df_logs, threshold=bruteforce_threshold)
    port_scan_df = detections.detect_portscan(df_logs, threshold=portscan_threshold)
    results["brute_force"] = brute_force_df
    results["port_scan"] = port_scan_df

    return results

uploaded_file, bruteforce_threshold, portscan_threshold= render_sidebar()
df_logs = load_logs(uploaded_file)
render_header()
if df_logs is None:
    st.info("No hay archivos, carga uno")
else:
    results = run_detections(df_logs, bruteforce_threshold, portscan_threshold)

    render_tabs(df_logs, results)

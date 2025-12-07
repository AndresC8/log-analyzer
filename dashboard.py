import streamlit as st
import pandas as pd
from analyzer import detections
import altair as alt
# from openai import OpenAI
# from analyzer.copilot import build_soc_summary, ask_soc_copilot

REQUIRED_AUTH_COLUMNS = {
    "timestamp", "event_type", "source_ip", "username"
}

st.markdown("""
<style>
    .block-container {
        padding-top: 1rem !important;
        padding-bottom: 1rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }
</style>
""", unsafe_allow_html=True)


st.set_page_config(
    page_title="SOC Analyzer Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

def render_sidebar():
    with st.sidebar:
        st.markdown("⚙️ Configuración")
        st.write("Sube un csv: ")
        
        uploaded_file = st.file_uploader(
            "SELECCIONAR ARCHIVO",
            type=["csv"],
            help="Carga los logs"
        )

        st.markdown("---")
        st.subheader("📊 Parámetros de detección")

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

        succes_bruteforce_threshold = st.slider(
            "Succes bruteforce",
            min_value=2,
            max_value=20,
            value=5,
        )

        window_minutes = st.number_input(
            "Tamañ de ventana",
            min_value = 1,
            max_value = 50,
            value = 5,
            step = 1 
        )

        st.markdown("---")
        st.caption("SOC Analyzer V2")

    return uploaded_file, bruteforce_threshold, portscan_threshold, succes_bruteforce_threshold, window_minutes

def load_logs(uploaded_file):
    df_logs = None

    if uploaded_file is None:
        return None
    df = pd.read_csv(uploaded_file)
    return df

def render_header():
    st.markdown("""
        <h1 style='color:#0EA5E9; margin-bottom:0;'>
            🛡️ SOC Analyzer Dashboard
        </h1>
        <p style='color:#9BA8B4; font-size:18px; margin-top:4px;'>
            Motor de detección, análisis de logs y visualización de anomalías.
        </p>
    """, unsafe_allow_html=True)
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

        df_bf = results.get("brute_force")

        if df_bf is None or df_bf.empty:
            st.success("No se detectaron ataques de fuerza bruta")
            return
        
        st.write("IPs con multiples intentos fallidos de autenticacion")
        st.dataframe(df_bf)

        ip_col = "source_ip"
        fail_col = "failures"

        if ip_col in df_bf.columns and fail_col in df_bf.columns:
            st.subheader("Intentos fallidos por IP de origen")

            chart = (
                alt.Chart(df_bf)
                .mark_bar()
                .encode(
                    x = alt.X(ip_col + ":N", title="IP origen", sort="-y"),
                    y = alt.Y(fail_col + ":Q", title="Intentos fallidos"),
                    tooltip=[ip_col, fail_col],
                    color = alt.Color(fail_col + ":Q", title="Intentos fallidos"),
                )
            )

            st.altair_chart(chart, use_container_width=True)
        else:
            st.warning(
                f"No se encontraron las columnas: {ip_col}, {fail_col}"
            )

    with tab3:
        st.subheader("🟢 Successful Brute Force")
        st.caption(
            "Detecta inicios de sesión exitosos que estuvieron precedidos por múltiples "
            "intentos fallidos desde la misma IP o contra la misma cuenta."
        )
        st.divider()

        df_sbf = results.get("successful_bruteforce") 
        if df_sbf is None or df_sbf.empty:
            st.success("No se detectaron logins sospechosos en el umbral actual")
        else:
            st.subheader("📋 Hallazgos")
            st.write(f"Total de cuentas comprometidas: {df_sbf.shape[0]}")
            st.dataframe(df_sbf)

            suspicious_ips = df_sbf["source_ip"].unique()

            df_graph = df_logs[df_logs["source_ip"].isin(suspicious_ips)]

            time_col = "timestamp"
            user_col = "username"

            if time_col in df_graph.columns and user_col in df_graph.columns:
                st.subheader("📊 Línea temporal de logins sospechosos")

                df_plot = df_graph.dropna(subset=[time_col]).copy()

                if not df_plot.empty:

                    df_plot = df_plot.sort_values(time_col)

                    chart = (
                        alt.Chart(df_plot)
                        .mark_circle(size=60, opacity=0.7)
                        .encode(
                            x = alt.X(time_col + ":T", title="Fecha y hora"),
                            y = alt.Y(user_col + ":N", title="Usuario"),
                            color=alt.Color(
                                "event_type:N",
                                title="Tipo de evento",
                                scale=alt.Scale(
                                    domain=["login_failed", "login_success"],
                                    range = ["#EF4444", "#22C55E"]
                                )
                            ),
                            tooltip=[
                                time_col,
                                user_col,
                                "source_ip",
                                "event_type"
                            ],
                        )
                        .interactive()
                    )
                    st.altair_chart(chart, use_container_width=True)
                else:
                    st.info("No hay eventos validos para graficar")
            else:
                st.info(
                    f"No se encontraron las columnas necesarias: {time_col}, {user_col}"
                )
            
    with tab4:
        st.subheader("📊 Portscan")
        df_pscan = results.get("port_scan")
        if df_pscan is None or df_pscan.empty:
            st.success("No se detectaron portscan") 
        else:
            st.write(f"IPs sospechosas: {df_pscan.shape[0]}")
            st.dataframe(df_pscan)
            st.markdown("IPs sospechosas por escaneo de puertos")

            col1, col2, col3 = st.columns(3)
            col1.metric("IPs sospechosas", df_pscan.shape[0])

            targets_col = "portscan"
            ip_col = "source_ip"

            if targets_col in df_pscan.columns:
                col2.metric("Destinos unicos totales", int(df_pscan[targets_col].sum()))
                col3.metric("Max. destinos por IP", int(df_pscan[targets_col].max()))
                st.divider()

            if ip_col in df_pscan.columns and targets_col in df_pscan.columns:
                st.subheader("Destinos distintos por IP origen")

                chart = (
                    alt.Chart(df_pscan)
                    .mark_bar()
                    .encode(
                        x = alt.X(
                            ip_col + ":N",
                            title = "IP origen",
                            sort = "-y"
                        ),
                        y = alt.Y(
                            targets_col + ":Q",
                            title="Destinos distintos alcanzados"
                        ),
                        color=alt.Color(
                            targets_col + ":Q",
                            title = "Destinos distintos",
                            scale=alt.Scale(scheme="teals")
                        ),
                        tooltip = [ip_col, targets_col],
                    )
                    
                )

                st.altair_chart(chart, use_container_width=True)
            else:
                st.info(f"No se encontraron las columnas necesarias: {ip_col}, {targets_col}")
                
    with tab5:
        st.subheader("⏰ Off-hours Logins")
        df_offhours = results.get("off_hours")
        
        if df_offhours is None or df_offhours.empty:
            st.success("No se detecrtó actividad")
            
        else:
            st.write("📋 Hallazgos")
            st.dataframe(df_offhours)

            time_col = "timestamp"
            user_col = "username"

            if time_col in df_offhours and user_col in df_offhours:
                st.subheader("📊 Línea temporal de logins off-hours")

                df_plot = df_offhours.dropna(subset=[time_col]).copy()

                if not df_plot.empty:
                    df_plot = df_plot.sort_values(time_col)

                    chart = (
                        alt.Chart(df_plot)
                        .mark_circle(size = 50, opacity = 0.7)
                        .encode(
                            x = alt.X(time_col + ":T", title="Fecha y hora"),
                            y = alt.Y(user_col + ":N", title="Username"),
                            color = alt.Color(
                                "event_type:N",
                                title = "Login success",
                                scale = alt.Scale(
                                    domain = ["login_success"],
                                    range = ["#22C55E"]
                                )
                            ),
                            tooltip=[
                                time_col,
                                user_col,
                                "source_ip",
                                "event_type"
                            ],
                        )
                        .interactive()
                    )
                    st.altair_chart(chart, use_container_width=True)

    with tab6:
        st.subheader("🔁 Password Spraying")
        st.write("Aquí estará la detección Password Spraying")

    with tab7:
        st.subheader("🤖 SOC Copilot IA")
        st.caption("Genera un alnalisis a partir de las detecciones actuales")
        st.divider()

        # if df_logs is None:
        #     st.info("Sube primero un csv de logs en la barra lateral")
        # elif not results:
        #     st.info("NO hayresultados de detecciones para analizar todavia")
        # else:
        #     with st.expander(
        #         "Ver resumen tecnico que se enviará a la IA",
        #         expanded=False
        #     ):

        #         summary_preview = build_soc_summary(results)
        #         st.text(summary_preview)

        #         if st.button("Generar analisis con IA"):
        #             with st.spinner("Analizando detecciones con SOC copilot..."):
        #                 summary_text = build_soc_summary(results)
        #                 ia_response = ask_soc_copilot(summary_text)

        #                 st.markdown("Informe generado por SOC copilot")
        #                 st.markdown(ia_response)

def run_detections(
        df_logs, 
        bruteforce_threshold,
        portscan_threshold,
        successbruteforce_threshold,
        window_minutes

):
    if df_logs is None:
        return {}
    
    results = {}
    brute_force_df = detections.detect_bruteforce(df_logs, threshold=bruteforce_threshold, window_minutes=window_minutes)
    port_scan_df = detections.detect_portscan(df_logs, threshold=portscan_threshold)
    success_brute_force_df = detections.detect_succesful_bruteforce(df_logs, threshold=successbruteforce_threshold)
    off_hours_df = detections.detect_offhours(df_logs, night_start=0, night_end=5)
    results["brute_force"] = brute_force_df
    results["port_scan"] = port_scan_df
    results["successful_bruteforce"] = success_brute_force_df
    results["off_hours"] = off_hours_df

    return results

def validate_auth_schema(df: pd.DataFrame):
    missing = [col for col in REQUIRED_AUTH_COLUMNS if col not in df.columns]
    return missing

(uploaded_file, 
 bruteforce_threshold, 
 portscan_threshold, 
 successbruteforce_threshold,
 window_minutes) = render_sidebar()

df_logs = load_logs(uploaded_file)
render_header()

if df_logs is not None:
    missing = validate_auth_schema(df_logs)

    if missing:
        st.error(
            "❌ El archivo cargado no tiene el formato esperado para logs de autenticación\n\n"
            "Columnas requeridas:\n"
            f"- {', '.join(sorted(REQUIRED_AUTH_COLUMNS))}\n\n"
            "Columnas faltantes:\n"
            f"- {', '.join(sorted(missing))}"
        )
        st.stop()

results = run_detections(
    df_logs, 
    bruteforce_threshold, 
    portscan_threshold, 
    successbruteforce_threshold,
    window_minutes,
)

if df_logs is not None:
    render_tabs(df_logs, results)



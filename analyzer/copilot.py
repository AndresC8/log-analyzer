from typing import Optional, Dict, Any
import os

try:
    from openai import OpenAI
except Exception:
    OpenAI = None


def get_openai_client():
    if OpenAI is None:
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return None

    return OpenAI(api_key=api_key)



def build_soc_summary(results: Dict[str, Any]):
    """

    Build a high-level text digest from the results dictionary

    in run_detections.

    Expect keys like:

    - "bruteforce"

    - "successful_bruteforce"

    - "port_scan"

    - "off_hours"

    - "password_spraying"

    """

    lines: list[str] = []
    lines.append("Resumen de detecciones SOC generado por el motor de análisis.\n")

    # bruteforce
    df_bf = results.get("bruteforce")
    if df_bf is not None and not df_bf.empty:
        lines.append("Brute force:")
        lines.append(f"- IPs sospechosas: {df_bf.shape[0]}")
        if {"source_ip", "failures"} <= set(df_bf.columns):
            top_bf = df_bf.sort_values("failures", ascending=False).head(5)
            for _, row in top_bf.iterrows():
                lines.append(
                    f"  • IP {row['source_ip']} con {row['failures']} intentos fallidos"
                )
        lines.append("")

    # succesfull bruteforce
    df_sbf = results.get("successful_bruteforce")
    if df_sbf is not None and not df_sbf.empty:
        lines.append("Successful brute force:")
        lines.append(f"- Posibles cuentas comprometidas: {df_sbf.shape[0]}")
        for _, row in df_sbf.head(5).iterrows():
            ip = row.get("source_ip", "desconocida")
            user = row.get("username", "desconocido")
            fails = row.get("failures", "N/A")
            lines.append(
                f"  • IP {ip} contra usuario {user} tras {fails} intentos fallidos"
            )
        lines.append("")

    # portscan
    df_ps = results.get("port_scan")
    if df_ps is not None and not df_ps.empty:
        lines.append("Portscan:")
        lines.append(f"- IPs con comportamiento de escaneo de puertos: {df_ps.shape[0]}")
        col_targets = "dest_port"  
        if {"source_ip", col_targets} <= set(df_ps.columns):
            top_ps = df_ps.sort_values(col_targets, ascending=False).head(5)
            for _, row in top_ps.iterrows():
                lines.append(
                    f"  • IP {row['source_ip']} alcanzó {row[col_targets]} puertos/targets distintos"
                )
        lines.append("")

    # off-hours login
    df_off = results.get("off_hours")
    if df_off is not None and not df_off.empty:
        lines.append("Off-hours logins:")
        lines.append(f"- Inicios de sesión fuera de horario detectados: {df_off.shape[0]}")
        if {"username", "timestamp"} <= set(df_off.columns):
            for _, row in df_off.head(5).iterrows():
                user = row.get("username", "desconocido")
                ts = row.get("timestamp", "sin_timestamp")
                lines.append(f"  • Usuario {user} con login fuera de horario en {ts}")
        lines.append("")

    # password spraying
    df_spr = results.get("password_spraying")
    if df_spr is not None and not df_spr.empty:
        lines.append("Password spraying:")
        lines.append(f"- IPs con patrón de password spraying: {df_spr.shape[0]}")
        if {"source_ip", "unique_users"} <= set(df_spr.columns):
            for _, row in df_spr.head(5).iterrows():
                lines.append(
                    f"  • IP {row['source_ip']} intentó autenticarse contra "
                    f"{row['unique_users']} usuarios distintos"
                )
        lines.append("")

    if len(lines) == 1:
        lines.append("No se detectaron eventos sospechosos en este conjunto de logs.")

    return "\n".join(lines)


def ask_soc_copilot(summary_text: str) -> str:

    if not summary_text or summary_text.strip() == "":
        return "No se proporcionó ningún resumen para analizar."
    
    client = get_openai_client()
    if client is None:
        return (
            "SOC Copilot deshabilitado: no se encontró 'OPENAI_API_KEY'"
        )

    system_prompt = (
        "Eres un analista SOC senior. Te pasaré un resumen de detecciones "
        "de un motor de análisis de logs (brute force, successful brute force, "
        "portscan, inicios de sesión fuera de horario y password spraying). "
        "Debes responder SIEMPRE en español, con un informe estructurado y claro "
        "para un equipo de ciberseguridad.\n\n"
        "Estructura de la respuesta:\n"
        "1. Resumen ejecutivo (no técnico, orientado a liderazgo)\n"
        "2. Detalles técnicos por tipo de detección\n"
        "3. Mapeo a MITRE ATT&CK (IDs y nombres de técnicas relevantes)\n"
        "4. Hipótesis sobre el ataque o campañas posibles\n"
        "5. Recomendaciones concretas de respuesta (IR) y hardening\n"
    )

    user_prompt = (
        "A continuación está el resumen de detecciones generado por el motor:\n\n"
        f"{summary_text}\n\n"
        "Genera el informe siguiendo la estructura indicada."
    )

    response = client.responses.create(
        model="gpt-4.1-mini",  
        input=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_output_tokens=900,
    )

    try:
        content = response.output[0].content[0].text
    except Exception:
        content = (
            "No se pudo extraer la respuesta del modelo. "
            "Revisa la configuración de la API o los logs."
        )

    return content
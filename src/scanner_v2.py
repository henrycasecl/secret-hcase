import os
import sys
import json
import requests
import argparse
from langgraph.graph import StateGraph, END

OLLAMA_HOST = "http://192.168.1.125:11434"

# ---------------------------------------------------------------------
# 🔹 Función utilitaria: llamada al modelo local
# ---------------------------------------------------------------------
def ollama_generate(prompt, model="gpt-oss:20b"):
    """Consulta a Ollama local"""
    try:
        response = requests.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": model, "prompt": prompt},
            timeout=300
        )
    except Exception as e:
        print(f"[!] Error al conectar con Ollama: {e}")
        return ""
    
    text = ""
    for line in response.iter_lines():
        if line:
            try:
                data = json.loads(line)
                text += data.get("response", "")
            except Exception:
                pass
    return text.strip()

# ---------------------------------------------------------------------
# 🔹 Estado del grafo
# ---------------------------------------------------------------------
class ScanState(dict):
    files: list
    findings: list
    path: str

# ---------------------------------------------------------------------
# 🔹 Nodo 1: Lectura de archivos
# ---------------------------------------------------------------------
def node_read_files(state: ScanState):
    path = state.get("path", ".")
    files = []

    if os.path.isfile(path):
        with open(path, "r", errors="ignore") as f:
            files.append({"path": path, "content": f.read()})
    else:
        for root, _, file_list in os.walk(path):
            for file in file_list:
                if file.endswith((".py", ".env", ".json", ".yaml", ".yml")): 
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", errors="ignore") as f:
                        files.append({"path": full_path, "content": f.read()})
    state["files"] = files
    print(f"[+] Archivos cargados (.py, .env, .json, .yaml, .yml): {len(files)} desde {path}")
    return state

# ---------------------------------------------------------------------
# 🔹 Nodo 2: Detección de secretos (con soporte # IGNORE)
# ---------------------------------------------------------------------
def node_detect_secrets(state: ScanState):
    findings = []
    print("[+] Detección de secretos. Para falsos positivos agregar '# IGNORE' en la linea del código, estos secretos no serán análizados")

    for file in state["files"]:
        lines = file["content"].splitlines()
        ignore_lines = [i + 1 for i, line in enumerate(lines) if "# IGNORE" in line]

        # Prompt para el modelo
        prompt = f"""
Eres un analista de seguridad.
Debes encontrar posibles secretos o credenciales dentro del código a continuación.
Devuelve SOLO una lista JSON, donde cada elemento tenga:
'tipo', 'valor'.

Código:
{file['content']}

Ejemplo de respuesta:
[{{"tipo":"password","valor":"mypwd123","linea":10}}]
Si no hay secretos, responde [].
"""
        response = ollama_generate(prompt)
        try:
            detected = json.loads(response)
        except Exception:
            print(f"[!] Respuesta no válida en {file['path']}")
            detected = []

        # Filtrar líneas que están marcadas con "# IGNORE"
        filtered = []
        for d in detected:
            try:
                line_num = int(d.get("linea", -1))
                if line_num in ignore_lines:
                    print(f"[-] Ignorando secreto en línea {line_num} (marcado con # IGNORE)")
                    continue
                d["archivo"] = file["path"]
                filtered.append(d)
            except Exception:
                continue

        findings.extend(filtered)

    state["findings"] = findings
    return state

# ---------------------------------------------------------------------
# 🔹 Nodo 3: Generación del reporte
# ---------------------------------------------------------------------
def node_generate_report(state: ScanState):
    print("\n[+] Informe de Detección de Secretos\n" + "=" * 40)
    if not state["findings"]:
        print("[+] No se detectaron secretos.")
        return state

    for f in state["findings"]:
        print(f"\n[+] Archivo: {f['archivo']}")
        print(f"   Tipo: {f['tipo']}")
        print(f"   Valor: {f['valor']}")
    print("\n[+] Escaneo completado.")
    return state

# ---------------------------------------------------------------------
# 🧩 Construcción del flujo LangGraph
# ---------------------------------------------------------------------
graph = StateGraph(ScanState)
graph.add_node("read_files", node_read_files)
graph.add_node("detect_secrets", node_detect_secrets)
graph.add_node("generate_report", node_generate_report)

graph.add_edge("read_files", "detect_secrets")
graph.add_edge("detect_secrets", "generate_report")
graph.set_entry_point("read_files")
graph.set_finish_point("generate_report")

app = graph.compile()

# ---------------------------------------------------------------------
# 🚀 Ejecución CLI
# ---------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Escáner IA de secretos en código fuente")
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Ruta del archivo o directorio a analizar (por defecto: .)"
    )
    args = parser.parse_args()
    path = args.path

    if not os.path.exists(path):
        print(f"[!] Error: la ruta '{path}' no existe.")
        sys.exit(1)

    print(f"[+] Iniciando flujo de detección de secretos IA sobre: {path}")
    app.invoke({"path": path})

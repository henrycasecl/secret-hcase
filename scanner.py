import os
import sys
import json
import requests
import argparse
from langgraph.graph import StateGraph, END
#from dotenv import load_dotenv

#load_dotenv()

OLLAMA_HOST = "http://192.168.1.125:11434"
FALSE_POSITIVES_FILE = "false_positives.json"

# ---------------------------------------------------------------------
# 🔹 Funciones utilitarias
# ---------------------------------------------------------------------
def load_false_positives():
    if os.path.exists(FALSE_POSITIVES_FILE):
        with open(FALSE_POSITIVES_FILE, "r") as f:
            return json.load(f)
    return []

def save_false_positives(data):
    with open(FALSE_POSITIVES_FILE, "w") as f:
        json.dump(data, f, indent=2)

def ollama_generate(prompt, model="gpt-oss:20b"):
    """Consulta a Ollama local"""
    response = requests.post(
        f"{OLLAMA_HOST}/api/generate",
        json={"model": model, "prompt": prompt},
        timeout=300
    )
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
# 🔹 Definición del estado del grafo
# ---------------------------------------------------------------------
class ScanState(dict):
    files: list
    findings: list
    false_positives: list
    path: str

# ---------------------------------------------------------------------
# 🔹 Nodo 1: Leer archivos del repositorio
# ---------------------------------------------------------------------
def node_read_files(state: ScanState):
    path = state.get("path", ".")
    files = []

    if os.path.isfile(path):
        with open(path, "r", errors="ignore") as f:
            files.append({"path": path, "content": f.read()})
    else:
        for root, _, file_list in os.walk("."):
            for file in file_list:
                if file.endswith((".py", ".env", ".json", ".yaml", ".yml")):
                    full_path = os.path.join(root, file)
                    with open(full_path, "r", errors="ignore") as f:
                        files.append({"path": full_path, "content": f.read()})
    state["files"] = files
    print(f"[+] Archivos cargados: {len(files)} desde {path}")
    return state

# ---------------------------------------------------------------------
# 🔹 Nodo 2: Agente detector de secretos
# ---------------------------------------------------------------------
def node_detect_secrets(state: ScanState):
    findings = []
    for file in state["files"]:
        prompt = f"""
Eres un agente experto en seguridad de código.
Analiza el siguiente archivo y devuelve una lista JSON de secretos encontrados,
donde cada elemento contenga: 'tipo', 'valor' y 'línea aproximada'.

Código:
{file['content']}

Responde SOLO JSON, por ejemplo:
[{{"tipo":"password","valor":"mypwd123","linea":10}}]
Si no hay secretos, responde [].
"""
        response = ollama_generate(prompt)
        try:
            detected = json.loads(response)
            for d in detected:
                d["archivo"] = file["path"]
            findings.extend(detected)
        except:
            print(f"[!] Respuesta no válida en {file['path']}")
    state["findings"] = findings
    #print(state)
    return state

# ---------------------------------------------------------------------
# 🔹 Nodo 3: Agente validador (falsos positivos)
# ---------------------------------------------------------------------
def node_validate_findings(state: ScanState):
    validated = []
    for f in state["findings"]:
        text = f"Tipo: {f['tipo']}\nValor: {f['valor']}\nArchivo: {f['archivo']}"
        prompt = f"""
Eres un auditor de seguridad. Evalúa si el siguiente hallazgo corresponde
a un secreto real o un falso positivo. Responde con "REAL" o "FALSO POSITIVO".

{text}
"""
        decision = ollama_generate(prompt).upper()
        f["veredicto"] = "REAL" if "REAL" in decision else "FALSO POSITIVO"
        validated.append(f)
    state["findings"] = validated
    return state

# ---------------------------------------------------------------------
# 🔹 Nodo 4: Registrar falsos positivos
# ---------------------------------------------------------------------
def node_update_false_positives(state: ScanState):
    false_positives = load_false_positives()
    for f in state["findings"]:
        if f["veredicto"] == "FALSO POSITIVO":
            entry = f"{f['archivo']}::{f['valor']}"
            if entry not in false_positives:
                false_positives.append(entry)
    save_false_positives(false_positives)
    state["false_positives"] = false_positives
    return state

# ---------------------------------------------------------------------
# 🔹 Nodo 5: Generar informe final
# ---------------------------------------------------------------------
def node_generate_report(state: ScanState):
    print("\n[+] Informe de Detección de Secretos\n" + "=" * 40)
    for f in state["findings"]:
        print(f"\n[+] Archivo: {f['archivo']}")
        print(f"   Tipo: {f['tipo']}")
        print(f"   Valor: {f['valor']}")
        #print(f"   Veredicto: {f['veredicto']}")
    print("\n[+] Escaneo completado.")
    return state

# ---------------------------------------------------------------------
# 🧩 Construcción del flujo LangGraph
# ---------------------------------------------------------------------
graph = StateGraph(ScanState)
graph.add_node("read_files", node_read_files)
graph.add_node("detect_secrets", node_detect_secrets)
#graph.add_node("validate_findings", node_validate_findings)
#graph.add_node("update_false_positives", node_update_false_positives)
graph.add_node("generate_report", node_generate_report)

graph.add_edge("read_files", "detect_secrets")
#graph.add_edge("detect_secrets", "validate_findings")
#graph.add_edge("validate_findings", "update_false_positives")
#graph.add_edge("update_false_positives", "generate_report")
graph.add_edge("detect_secrets", "generate_report")
graph.set_entry_point("read_files")
graph.set_finish_point("generate_report")

app = graph.compile()

# ---------------------------------------------------------------------
# 🚀 Ejecución
# ---------------------------------------------------------------------
if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Escáner IA de secretos en código fuente")
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="Ruta del directorio o archivo a analizar (por defecto: directorio actual)",
    )
    args = parser.parse_args()

    path = args.path
    if not os.path.exists(path):
        print(f"[!] Error: la ruta '{path}' no existe.")
        sys.exit(1)

    print(f"[+] Iniciando flujo de detección de secretos con agentes IA sobre: {path}")
    app.invoke({"path": path})


import os
import subprocess
import nest_asyncio
import uvicorn
import re
import base64
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional, Dict, Any

# --- CONFIGURACIÓN DE ENERGÍA (Ruta ADB) ---
# Buscamos el equilibrio: primero la intención explícita (Variable de Entorno),
# luego la ruta natural del entorno local (Windows Default), y finalmente la omnipresencia del sistema (PATH).

env_adb = os.environ.get("ADB_PATH")
local_adb = os.path.join(os.path.expanduser("~"), r"AppData\Local\Android\Sdk\platform-tools\adb.exe")

if env_adb:
    ADB_PATH = env_adb
elif os.path.exists(local_adb):
    ADB_PATH = local_adb
else:
    ADB_PATH = "adb"

# Validación final de existencia para asegurar que el flujo no se bloquee
if not os.path.exists(ADB_PATH) and ADB_PATH != "adb":
    print(f"Nota: No se encontró ADB en la ruta detectada ({ADB_PATH}). Usando 'adb' del sistema.")
    ADB_PATH = "adb"

nest_asyncio.apply()

app = FastAPI(title="Holistic Mobile Auditor", description="API consciente para auditoría ADB")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- UTILIDADES ---

def run_adb_command(command: List[str], binary_mode: bool = False, check_exit_code: bool = True):
    try:
        full_command = [ADB_PATH] + command
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=not binary_mode, 
            check=check_exit_code,
            encoding='utf-8' if not binary_mode else None, 
            errors='replace' if not binary_mode else None
        )
        if binary_mode: return result.stdout 
        else: return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = e.stderr if e.stderr else str(e)
        # Algunos comandos como 'ls' pueden devolver exit code != 0 pero dar info útil
        if not check_exit_code:
            return e.stdout if e.stdout else ""
        raise HTTPException(status_code=500, detail=f"Error en el flujo ADB: {error_msg}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"ADB no encontrado en: {ADB_PATH}. Verifica la ruta.")

def extract_strings_from_bytes(data: bytes, min_length: int = 4) -> List[str]:
    try:
        text = data.decode('utf-8', errors='ignore')
        pattern = r"[ -~]{" + str(min_length) + r",}"
        return re.findall(pattern, text)
    except Exception:
        return []

def get_app_links_state(device_id: str, package_name: str) -> Dict[str, Any]:
    """
    Consulta el estado de verificación de App Links (Android 12+).
    Identifica bloqueos en la confianza entre Dominio y App.
    """
    try:
        cmd = ["-s", device_id, "shell", "pm", "get-app-links", "--user", "0", package_name]
        output = run_adb_command(cmd, check_exit_code=False)
        
        domains = []
        
        # Parseo simple basado en la estructura de salida estándar
        # Buscamos líneas como: "  example.com: 1024" dentro de "Domain verification state:"
        
        # Extraer sección de estado de verificación
        verification_section = re.search(r"Domain verification state:(.*?)(User 0:|$)", output, re.DOTALL)
        if verification_section:
            block = verification_section.group(1)
            # Encontrar dominios y sus códigos de estado
            matches = re.findall(r"\s+([\w\.-]+):\s+(\d+)", block)
            for domain, state_code in matches:
                state_desc = "Unknown"
                status = "warning" # Default state
                
                code = int(state_code)
                # Códigos comunes:
                # 0: STATE_NO_RESPONSE
                # 1: STATE_VERIFIED (Éxito / Sattva)
                # 2: STATE_APPROVED (Aprobado por usuario)
                # 3: STATE_DENIED
                # 1024: STATE_LEGACY_USER (Fallo de verificación automática / Rajas)
                
                if code == 1: 
                    state_desc = "Verified (Automatic)"
                    status = "success"
                elif code == 2:
                    state_desc = "Approved (User)"
                    status = "success"
                elif code == 1024:
                    state_desc = "Legacy/Unverified (1024)"
                    status = "warning"
                else:
                    state_desc = f"State Code: {code}"
                    status = "danger"

                # Verificar si está explícitamente deshabilitado por el usuario
                is_disabled = False
                if f"Disabled:\n" in output and domain in output.split("Disabled:")[1]:
                     is_disabled = True
                     status = "danger"
                     state_desc += " [USER DISABLED]"

                domains.append({
                    "domain": domain,
                    "code": code,
                    "description": state_desc,
                    "status": status
                })

        return {"domains": domains, "raw": output}
    except Exception as e:
        print(f"Error obteniendo app links: {e}")
        return {"domains": [], "raw": str(e)}

def analyze_security_posture(raw_data: str) -> Dict[str, Any]:
    analysis = {
        "version_name": "Unknown", "version_code": "Unknown", "user_id": "Unknown",
        "data_dir": "Unknown", 
        "permissions": [], "granted_permissions": [], 
        "schemes": [], "providers": [], 
        "intent_actions": [], "intent_categories": [],
        "is_debuggable": False
    }
    try:
        v_name = re.search(r"versionName=([^\s]+)", raw_data)
        if v_name: analysis["version_name"] = v_name.group(1)
        
        v_code = re.search(r"versionCode=(\d+)", raw_data)
        if v_code: analysis["version_code"] = v_code.group(1)
        
        uid = re.search(r"userId=(\d+)", raw_data)
        if uid: analysis["user_id"] = uid.group(1)
        elif "appId=" in raw_data:
             app_id = re.search(r"appId=(\d+)", raw_data)
             if app_id: analysis["user_id"] = app_id.group(1)

        data_dir = re.search(r"dataDir=([^\s]+)", raw_data)
        if data_dir: analysis["data_dir"] = data_dir.group(1)

        if "DEBUGGABLE" in raw_data or "debuggable=true" in raw_data: analysis["is_debuggable"] = True

        perm_block_match = re.search(r"requested permissions:(.*?)(install permissions:|User \d|runtime permissions:)", raw_data, re.DOTALL)
        if perm_block_match:
            perm_block = perm_block_match.group(1)
            perms = re.findall(r"(android\.permission\.[\w_]+|com\.[\w\.]+\.permission\.[\w_]+)", perm_block)
            analysis["permissions"] = sorted(list(set(perms))) 

        granted_matches = re.findall(r"([\w\.]+\.permission\.[\w\_]+):\s*granted=true", raw_data)
        install_perm_block = re.search(r"install permissions:(.*?)(User \d|runtime permissions:)", raw_data, re.DOTALL)
        if install_perm_block:
            install_perms = re.findall(r"([\w\.]+\.permission\.[\w\_]+)", install_perm_block.group(1))
            granted_matches.extend(install_perms)
            
        analysis["granted_permissions"] = sorted(list(set(granted_matches)))

        scheme_matches = re.findall(r"Scheme: \"([^\"]+)\"", raw_data)
        filtered_schemes = [s for s in set(scheme_matches) if s not in ["android.intent.category.DEFAULT", "android.intent.category.BROWSABLE"]]
        analysis["schemes"] = sorted(filtered_schemes)

        provider_matches = re.findall(r"Provider\{[a-f0-9]+\s+([^\s]+)\}", raw_data)
        analysis["providers"] = sorted(list(set(provider_matches)))

        # --- PARSING DE INTENCIONES (Acciones y Categorías) ---
        actions_found = re.findall(r'Action: "([^"]+)"', raw_data)
        categories_found = re.findall(r'Category: "([^"]+)"', raw_data)
        
        analysis["intent_actions"] = sorted(list(set(actions_found)))
        analysis["intent_categories"] = sorted(list(set(categories_found)))

    except Exception as e:
        print(f"Error parseando seguridad: {e}")
    return analysis

def parse_ls_output(output: str) -> List[Dict[str, Any]]:
    files = []
    lines = output.split('\n')
    for line in lines:
        line = line.strip()
        if not line or line.startswith("total "): continue
        try:
            parts = line.split()
            if len(parts) < 7: continue
            perms = parts[0]
            is_dir = perms.startswith('d')
            is_link = perms.startswith('l')
            date_idx = -1
            for i, p in enumerate(parts):
                if re.match(r"\d{4}-\d{2}-\d{2}", p):
                    date_idx = i
                    break
            if date_idx != -1:
                size = parts[date_idx-1]
                date_str = f"{parts[date_idx]} {parts[date_idx+1]}"
                name_part = " ".join(parts[date_idx+2:])
                files.append({
                    "name": name_part,
                    "type": "dir" if is_dir else ("link" if is_link else "file"),
                    "size": size,
                    "date": date_str,
                    "perms": perms,
                    "raw": line
                })
        except Exception as e:
            # print(f"Error parsing line '{line}': {e}") # Silent error for cleaner logs
            pass
    return files

# --- ENDPOINTS ---

@app.get("/devices")
def list_devices():
    try:
        output = run_adb_command(["devices"])
        lines = output.split('\n')[1:] 
        devices = []
        for line in lines:
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 2:
                    devices.append({"id": parts[0], "status": parts[1]})
        return {"devices": devices}
    except Exception as e:
        return {"devices": []}

@app.get("/packages/{device_id}")
def list_packages_detailed(device_id: str):
    try:
        cmd_simple = ["-s", device_id, "shell", "pm", "list", "packages"]
        output_simple = run_adb_command(cmd_simple)
        package_names = [line.replace("package:", "").strip() for line in output_simple.split('\n') if line.strip()]
        try:
            cmd_dump = ["-s", device_id, "shell", "dumpsys", "package"]
            dump_output = run_adb_command(cmd_dump)
            pkg_data = {}
            current_pkg = None
            lines = dump_output.split('\n')
            for i, line in enumerate(lines):
                line = line.strip()
                pkg_match = re.search(r"^Package \[(.*?)\]", line)
                if pkg_match:
                    current_pkg = pkg_match.group(1)
                    if current_pkg not in pkg_data: pkg_data[current_pkg] = {"name": current_pkg, "installTime": None, "timeStamp": None, "updateTime": None}
                if current_pkg:
                    if "firstInstallTime=" in line: pkg_data[current_pkg]["installTime"] = line.split("firstInstallTime=")[1].strip()
                    elif "timeStamp=" in line: pkg_data[current_pkg]["timeStamp"] = line.split("timeStamp=")[1].strip()
                    elif "lastUpdateTime=" in line: pkg_data[current_pkg]["updateTime"] = line.split("lastUpdateTime=")[1].strip()
            final_list = []
            for name in package_names:
                raw = pkg_data.get(name, {})
                install_t = raw.get("installTime") or raw.get("timeStamp") or "N/A"
                update_t = raw.get("updateTime", "N/A")
                final_list.append({"name": name, "installTime": install_t, "updateTime": update_t})
            return {"device_id": device_id, "total_count": len(final_list), "packages": final_list}
        except Exception:
            return {"device_id": device_id, "total_count": len(package_names), "packages": [{"name": p, "installTime": "-", "updateTime": "-"} for p in package_names]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/package/{device_id}/{package_name}/details")
def get_single_package_details(device_id: str, package_name: str):
    try:
        # 1. Dumpsys principal
        cmd = ["-s", device_id, "shell", "dumpsys", "package", package_name]
        raw_output = run_adb_command(cmd)
        analysis = analyze_security_posture(raw_output)
        
        # 2. Análisis de App Links (Específico de tu solicitud)
        app_links_data = get_app_links_state(device_id, package_name)
        analysis["app_links"] = app_links_data["domains"]
        analysis["app_links_raw"] = app_links_data["raw"]

        return {"package": package_name, "analysis": analysis, "raw_info": raw_output}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/files/{device_id}")
def list_files_in_path(device_id: str, path: str):
    try:
        cmd = ["-s", device_id, "shell", "ls", "-l", path]
        output = run_adb_command(cmd, check_exit_code=False)
        
        if "Permission denied" in output:
            return {"path": path, "error": "Permission Denied (Try run-as or root)", "files": []}
        if "No such file" in output:
             return {"path": path, "error": "Path not found", "files": []}
             
        files = parse_ls_output(output)

        try:
            safe_path = path.replace('"', '\\"')
            cmd_magic = ["-s", device_id, "shell", f"cd \"{safe_path}\" && file *"]
            magic_output = run_adb_command(cmd_magic, check_exit_code=False)
            
            magic_map = {}
            for line in magic_output.split('\n'):
                line = line.strip()
                if ": " in line:
                    parts = line.split(": ", 1)
                    if len(parts) == 2:
                        fname = parts[0].strip()
                        if fname.startswith("./"): fname = fname[2:]
                        fname = fname.strip("'").strip('"')
                        desc = parts[1].strip()
                        magic_map[fname] = desc
            
            for f in files:
                if f['type'] == 'file':
                    f['magic'] = magic_map.get(f['name'], None)

        except Exception:
            pass

        files.sort(key=lambda x: (x['type'] != 'dir', x['name']))
        return {"path": path, "files": files}
    except Exception as e:
         return {"path": path, "error": str(e), "files": []}

@app.get("/files/{device_id}/read")
def read_file_content(device_id: str, path: str):
    try:
        cmd = ["-s", device_id, "shell", "cat", path]
        raw_bytes = run_adb_command(cmd, binary_mode=True)
        decoded_content = raw_bytes.decode('utf-8', errors='replace')
        strings = extract_strings_from_bytes(raw_bytes)
        b64_content = base64.b64encode(raw_bytes).decode('utf-8')

        return {
            "path": path,
            "size": len(raw_bytes),
            "content": decoded_content,
            "strings": strings,
            "base64": b64_content 
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/logs/{device_id}")
def get_logs(device_id: str, query: str):
    try:
        cmd = ["-s", device_id, "shell", f"logcat -d | grep {query}"]
        logs = run_adb_command(cmd, check_exit_code=False)
        if not logs: return {"query": query, "logs": "--- Silencio: No se encontraron registros recientes ---"}
        return {"query": query, "logs": logs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
def read_root():
    try:
        try: current_dir = os.path.dirname(os.path.abspath(__file__))
        except NameError: current_dir = os.getcwd()
        file_path = os.path.join(current_dir, "index.html")
        if not os.path.exists(file_path): file_path = "index.html"
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f: return f.read()
        else: return HTMLResponse(content="<h1>Error: index.html no encontrado</h1>", status_code=404)
    except Exception as e: return HTMLResponse(content=f"<h1>Error interno</h1><p>{str(e)}</p>", status_code=500)

if __name__ == "__main__":
    print(f"Iniciando servidor consciente. Usando ADB en: {ADB_PATH}")
    uvicorn.run(app, host="127.0.0.1", port=8000)
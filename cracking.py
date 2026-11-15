import subprocess
import re


def crackear(archivo_cap: str, bssid: str, diccionario: str) -> dict:
    
    # Corre aircrack-ng con el diccionario sobre el handshake y devuelve la contraseña

    comando = [
        "aircrack-ng",
        "-b", bssid,
        "-w", diccionario,
        archivo_cap
    ]

    resultado = subprocess.run(
        comando,
        capture_output=True,
        text=True
    )

    salida = resultado.stdout
    contrasena = _extraer_contrasena(salida)
    return {
        "encontrada": contrasena is not None,
        "contrasena": contrasena,
        "paquetes_leidos": _extraer_paquetes_leidos(salida),
        "claves_probadas": _extraer_claves_probadas(salida),
        "salida_completa": salida,
    }


def _extraer_contrasena(salida: str):
    coincidencia = re.search(r"KEY FOUND! \[ (.+) \]", salida)
    if coincidencia:
        return coincidencia.group(1)
    return None


def _extraer_paquetes_leidos(salida: str):
    coincidencia = re.search(r"Read (\d+) packets", salida)
    if coincidencia:
        return int(coincidencia.group(1))
    return None


def _extraer_claves_probadas(salida: str):
    coincidencia = re.search(r"(\d+)/\d+ keys tested", salida)
    if coincidencia:
        return int(coincidencia.group(1))
    return None
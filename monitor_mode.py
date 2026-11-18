import subprocess #Librería para ejecutar comandos en terminal


def iniciar_modo_monitor(interfaz: str) -> str:
    
    # Comando a ejecutar para iniciar el modo monitor en la terminal   

    resultado = subprocess.run(
        ["sudo", "airmon-ng", "start", interfaz],
        capture_output=True,
        text=True
    )
    
    # Capturamos la salida del comando y la imprimimos en la terminal
    salida = resultado.stdout + resultado.stderr
    print(salida)
    
    # Comprobación de que el modo monitor se haya activado correctamente
    if "monitor mode enabled" not in salida:
        raise RuntimeError("No se pudo activar el modo monitor. Revisa la salida arriba.")
    
    return _buscar_interfaz_en_modo_monitor()

def _buscar_interfaz_en_modo_monitor() -> str:
    # Corre 'iw dev' y recorre su salida buscando cuál interfaz está actualmente en modo monitor.
    
    resultado = subprocess.run(["iw", "dev"], capture_output=True, text=True)
    salida = resultado.stdout

    nombre_actual = None
    for linea in salida.splitlines():
        linea = linea.strip()
        if linea.startswith("Interface"):
            nombre_actual = linea.split()[1]
        elif linea.startswith("type monitor") and nombre_actual:
            return nombre_actual

    raise RuntimeError("No se encontró ninguna interfaz en modo monitor.")
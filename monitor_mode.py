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
    
    interfaz_monitor = f"{interfaz}mon"
    return interfaz_monitor
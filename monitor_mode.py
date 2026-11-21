
import subprocess
import time


def verificar_modo_monitor(interfaz: str) -> bool:
    """Comprueba si una interfaz está en modo monitor."""

    resultado = subprocess.run(
        ["iw", "dev", interfaz, "info"],
        capture_output=True,
        text=True,
        check=False,
        timeout=10
    )

    if resultado.returncode != 0:
        raise RuntimeError(
            f"No se pudo consultar {interfaz}: "
            f"{resultado.stderr.strip()}"
        )

    return any(
        linea.strip() == "type monitor"
        for linea in resultado.stdout.splitlines()
    )


def iniciar_modo_monitor(interfaz: str) -> str:
    """
    Verifica el modo monitor y lo activa cuando es necesario.

    Devuelve el nombre de la interfaz configurada.
    """

    print(f"Verificando interfaz {interfaz}...")

    # Si ya está en modo monitor, no modificar nada.
    if verificar_modo_monitor(interfaz):
        print(f"[OK] {interfaz} ya está en modo monitor.")
        return interfaz

    print(
        f"[INFO] {interfaz} no está en modo monitor."
    )
    print("[INFO] Intentando activarlo automáticamente...")

    # Intentar activar el modo monitor.
    resultado = subprocess.run(
        ["airmon-ng", "start", interfaz],
        capture_output=True,
        text=True,
        check=False,
        timeout=30
    )

    if resultado.returncode != 0:
        raise RuntimeError(
            "No se pudo activar el modo monitor:\n"
            + resultado.stdout
            + resultado.stderr
        )

    # Dar tiempo al controlador para actualizar la interfaz.
    time.sleep(2)

    # Algunos controladores pueden cambiar el nombre.
    candidatos = [interfaz, f"{interfaz}mon"]

    for candidato in candidatos:
        try:
            if verificar_modo_monitor(candidato):
                print(
                    f"[OK] Modo monitor activado en {candidato}."
                )
                return candidato
        except RuntimeError:
            continue

    raise RuntimeError(
        "Airmon-ng terminó, pero no se encontró una "
        "interfaz configurada en modo monitor."
    )

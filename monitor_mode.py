
import subprocess


def verificar_modo_monitor(interfaz: str) -> bool:
    """Comprueba si la interfaz ya está en modo monitor."""

    resultado = subprocess.run(
        ["iw", "dev", interfaz, "info"],
        capture_output=True,
        text=True,
        check=False
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
    """Comprueba el estado de la interfaz inalámbrica."""

    print(f"Verificando interfaz {interfaz}...")

    if verificar_modo_monitor(interfaz):
        print(
            f"[OK] {interfaz} ya está en modo monitor."
        )
        return interfaz

    raise RuntimeError(
        f"La interfaz {interfaz} no está en modo monitor. "
        "Configúrala antes de continuar."
    )

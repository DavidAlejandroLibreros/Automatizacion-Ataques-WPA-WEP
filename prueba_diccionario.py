"""Prueba offline del analizador WPA/WPA2 con una captura autorizada.

No captura Wi-Fi, no desconecta dispositivos y no imprime contraseñas.
Ejemplo:
  python3 prueba_diccionario.py --cap captura_manual-01.cap \
    --bssid AA:BB:CC:DD:EE:FF --diccionario diccionarios/comunes.txt
"""
from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

from cracking import crackear


def pruebas_simuladas() -> None:
    """Comprueba ejecución real del wrapper y su interpretación, sin Aircrack-ng."""
    import tempfile

    with tempfile.TemporaryDirectory() as temporal:
        carpeta = Path(temporal)
        cap = carpeta / "laboratorio.cap"
        lista = carpeta / "candidatas.txt"
        cap.write_bytes(b"PCAP_SIMULADO_NO_REAL")
        lista.write_text("ejemplo-falso\n", encoding="utf-8")
        casos = [
            ("Read 123 packets.\nKEY FOUND! [ ejemplo-falso ]\n50/100 keys tested", True, 123, 50),
            ("Read 123 packets.\nPassphrase not in dictionary\n100/100 keys tested", False, 123, 100),
        ]
        for salida, exito, paquetes, claves in casos:
            with patch("cracking.subprocess.run", return_value=SimpleNamespace(
                stdout=salida, stderr="", returncode=0
            )) as ejecutor:
                resultado = crackear(str(cap), "AA:BB:CC:DD:EE:FF", str(lista))
                assert resultado["encontrada"] is exito
                assert resultado["paquetes_leidos"] == paquetes
                assert resultado["claves_probadas"] == claves
                ejecutor.assert_called_once()
                comando = ejecutor.call_args.args[0]
                assert comando[0] == "aircrack-ng" and "-b" in comando and "-w" in comando
    print("[OK] Integración simulada: coincidencia y ausencia de coincidencia")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validar cracking.py con capturas de laboratorio autorizadas")
    parser.add_argument("--cap", type=Path, help="Archivo .cap de laboratorio")
    parser.add_argument("--bssid", help="BSSID de la red de laboratorio")
    parser.add_argument("--diccionario", type=Path, help="Diccionario local de candidatas")
    args = parser.parse_args()
    pruebas_simuladas()

    argumentos = [args.cap, args.bssid, args.diccionario]
    if all(valor is None for valor in argumentos):
        print("[INFO] Para la prueba real proporciona --cap, --bssid y --diccionario")
        return 0
    if any(valor is None for valor in argumentos):
        parser.error("Debes proporcionar juntos --cap, --bssid y --diccionario")

    print("Analizando la captura offline; la contraseña no se mostrará.")
    try:
        resultado = crackear(str(args.cap), args.bssid, str(args.diccionario))
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"[ERROR] {exc}")
        return 1

    print("Coincidencia encontrada:", "Sí" if resultado["encontrada"] else "No")
    print("Paquetes leídos:", resultado["paquetes_leidos"] if resultado["paquetes_leidos"] is not None else "No informados")
    print("Candidatas probadas:", resultado["claves_probadas"] if resultado["claves_probadas"] is not None else "No informadas")
    print("[OK] Prueba offline finalizada")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

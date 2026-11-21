import tempfile
from pathlib import Path

from escaneo import _parsear_csv_redes

CSV_EJEMPLO = """BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
AA:BB:CC:DD:EE:FF, 2026-11-21 10:00:00, 2026-11-21 10:00:10, 6, 54, WPA2, CCMP, PSK, -50, 20, 0, 0.0.0.0, 10, RedPrueba,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
11:22:33:44:55:66, 2026-11-21 10:00:00, 2026-11-21 10:00:10, -60, 15, AA:BB:CC:DD:EE:FF,
"""

with tempfile.TemporaryDirectory() as carpeta:
    archivo = Path(carpeta) / "escaneo-01.csv"
    archivo.write_text(CSV_EJEMPLO, encoding="utf-8")

    redes, clientes = _parsear_csv_redes(str(archivo))

    assert len(redes) == 1
    assert redes[0]["essid"] == "RedPrueba"
    assert redes[0]["canal"] == "6"

    assert len(clientes) == 1
    assert clientes[0]["mac_cliente"] == "11:22:33:44:55:66"

    print("[OK] Procesamiento de redes correcto.")
    print("[OK] Procesamiento de estaciones correcto.")
    print("Redes:", redes)
    print("Clientes:", clientes)

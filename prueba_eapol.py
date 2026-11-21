"""Pruebas sin radio de progreso EAPOL. Busca main.py después de renombrar."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

RUTA = Path(__file__).with_name("main.py")
if not RUTA.is_file() or "def contar_eapol_provisional(" not in RUTA.read_text(encoding="utf-8"):
    RUTA = Path(__file__).with_name("main_eapol.py")
spec = importlib.util.spec_from_file_location("main_eapol", RUTA)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class PruebasEapol(unittest.TestCase):
    def test_archivo_inexistente(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.object(mod.subprocess, "run") as run:
                self.assertIsNone(mod.contar_eapol_provisional(Path(d) / "nada.cap"))
                run.assert_not_called()

    def test_conteo_provisional(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "test.cap"
            ruta.write_bytes(b"datos de prueba")
            r = SimpleNamespace(returncode=0, stdout="1\n3\n7\n")
            with patch.object(mod.subprocess, "run", return_value=r) as run:
                self.assertEqual(mod.contar_eapol_provisional(ruta), 3)
                self.assertIn("eapol", run.call_args.args[0])

    def test_fallo_de_lectura_no_equivale_a_cero(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "test.cap"
            ruta.write_bytes(b"datos de prueba")
            r = SimpleNamespace(returncode=1, stdout="", stderr="truncado")
            with patch.object(mod.subprocess, "run", return_value=r):
                self.assertIsNone(mod.contar_eapol_provisional(ruta))

    def test_sin_eapol_es_cero(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "test.cap"
            ruta.write_bytes(b"datos de prueba")
            r = SimpleNamespace(returncode=0, stdout="")
            with patch.object(mod.subprocess, "run", return_value=r):
                self.assertEqual(mod.contar_eapol_provisional(ruta), 0)

    def test_captura_se_cierra_aun_con_error(self):
        proceso = SimpleNamespace(poll=lambda: 0)
        with patch.object(mod, "iniciar_captura_dirigida", return_value=(proceso, 22)), \
             patch.object(mod, "ruta_captura", return_value="/tmp/cap.cap"), \
             patch.object(mod, "detener_captura") as cerrar:
            with self.assertRaisesRegex(RuntimeError, "inesperadamente"):
                mod.capturar_un_minuto("wlan0", "AA:BB:CC:DD:EE:FF", 9, 60)
            cerrar.assert_called_once_with(proceso, 22)


if __name__ == "__main__":
    unittest.main(verbosity=2)

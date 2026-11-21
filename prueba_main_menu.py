"""Pruebas offline del controlador. No utiliza ni modifica el adaptador Wi-Fi."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

RUTA = Path(__file__).with_name('main.py')
spec = importlib.util.spec_from_file_location('main', RUTA)
modulo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(modulo)


class PruebaControlador(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.capturas = self.base / 'capturas_ataque'
        self.capturas.mkdir()
        self.diccionarios = self.base / 'diccionarios'
        self.diccionarios.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(modulo, 'BASE', self.base).start()
        patch.object(modulo, 'DICCIONARIOS', self.diccionarios).start()

    def test_limpieza_solo_temporales_propios(self):
        temporal = self.capturas / 'auditoria_tmp-01.cap'
        otro = self.capturas / 'captura_manual-01.cap'
        registro = self.capturas / 'auditoria_tmp-airodump.log'
        temporal.write_bytes(b'cap')
        otro.write_bytes(b'manual')
        registro.write_text('log')
        self.assertEqual(modulo.limpiar_temporales(), 2)
        self.assertTrue(otro.exists())
        self.assertFalse(temporal.exists())

    def _simular_sesion(self, handshake=False, diccionario=False):
        red = {'essid':'LAB', 'bssid':'AA:BB:CC:DD:EE:FF', 'canal':'9', 'cifrado':'WPA2'}
        ruta = self.capturas / 'auditoria_tmp-01.cap'
        def crear(*a):
            ruta.write_bytes(b'cap')
            return ruta, 1.0
        patch.object(modulo, 'escanear_redes', return_value=([red], [])).start()
        patch.object(modulo, 'seleccionar', return_value=0).start()
        patch.object(modulo, 'capturar_un_minuto', side_effect=crear).start()
        patch.object(modulo, 'diagnosticar_pcap', return_value={'tramas':10,'eapol':4 if handshake else 0,'truncado':False,'error':None}).start()
        patch.object(modulo, 'confirmar_handshake', return_value={'confirmado':handshake,'cantidad':int(handshake)}).start()
        mock_crack = patch.object(modulo, 'crackear', return_value={'encontrada':True,'contrasena':'TESTONLY123','claves_probadas':10}).start()
        if diccionario:
            lista = self.diccionarios / 'test.txt'
            lista.write_text('TESTONLY123\n')
        return ruta, mock_crack

    def test_sin_handshake_no_analiza_y_limpia(self):
        ruta, crack = self._simular_sesion()
        self.assertFalse(modulo.ejecutar_sesion('wlan0', 1, 1))
        crack.assert_not_called()
        self.assertFalse(ruta.exists())

    def test_con_handshake_analiza_y_limpia(self):
        ruta, crack = self._simular_sesion(handshake=True, diccionario=True)
        self.assertTrue(modulo.ejecutar_sesion('wlan0', 1, 1))
        crack.assert_called_once()
        self.assertFalse(ruta.exists())

    def test_pcap_invalido_no_intenta_crackear(self):
        ruta, crack = self._simular_sesion(handshake=True, diccionario=True)
        patch.object(modulo, 'diagnosticar_pcap', return_value={'tramas':1,'eapol':0,'truncado':True,'error':None}).start()
        self.assertFalse(modulo.ejecutar_sesion('wlan0', 1, 1))
        crack.assert_not_called()
        self.assertFalse(ruta.exists())

    def test_seleccion_cancela(self):
        with patch('builtins.input', return_value='q'):
            with self.assertRaises(KeyboardInterrupt):
                modulo.seleccionar(2, 'Opción')

    def test_menu_salir_no_exige_permisos(self):
        with patch.object(modulo, 'argumentos'), patch.object(modulo, 'seleccionar', return_value=1), patch.object(modulo.os, 'geteuid', return_value=1000):
            self.assertEqual(modulo.main(), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)

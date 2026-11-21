"""Pruebas de regresión sin radio ni contraseñas reales.

Ejecutar: python3 prueba_auditoria_final.py
"""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import main
from escaneo import _parsear_csv_redes
from cracking import interpretar_salida
from handshake import interpretar_listado
from ataque import diagnosticar_pcap
from monitor_mode import verificar_modo_monitor, iniciar_modo_monitor
from types import SimpleNamespace
from prueba_integracion_cap import inspeccion_basica_pcap


class AuditoriaFinal(unittest.TestCase):
    def test_cliente_seleccionado_devuelve_solo_mac(self):
        estaciones = [{"mac_cliente": "11:22:33:44:55:66", "bssid_conectado": "AA:BB:CC:DD:EE:FF"}]
        with patch.object(main, 'seleccionar', return_value=0):
            self.assertEqual(main.elegir_estacion(estaciones, "AA:BB:CC:DD:EE:FF"), "11:22:33:44:55:66")

    def test_omitir_cliente_devuelve_none(self):
        estaciones = [{"mac_cliente": "11:22:33:44:55:66", "bssid_conectado": "AA:BB:CC:DD:EE:FF"}]
        with patch.object(main, 'seleccionar', return_value=1):
            self.assertIsNone(main.elegir_estacion(estaciones, "AA:BB:CC:DD:EE:FF"))

    def test_no_hay_estaciones(self):
        self.assertIsNone(main.elegir_estacion([], "AA:BB:CC:DD:EE:FF"))

    def test_ciclo_con_cliente_no_exige_diccionario_sin_handshake(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            (base / 'capturas_ataque').mkdir()
            ruta = base / 'capturas_ataque' / 'auditoria_tmp-01.cap'
            def captura(*args):
                ruta.write_bytes(b'contenido simulado')
                return ruta, 0.01
            red = {'bssid':'AA:BB:CC:DD:EE:FF','canal':'6','cifrado':'WPA2','essid':'LAB'}
            est = {'mac_cliente':'11:22:33:44:55:66','bssid_conectado': red['bssid']}
            salida = io.StringIO()
            with patch.object(main,'BASE',base), \
                 patch.object(main,'escanear_redes',return_value=([red],[est])), \
                 patch.object(main,'seleccionar',side_effect=[0,0]), \
                 patch.object(main,'capturar_un_minuto',side_effect=captura), \
                 patch.object(main,'diagnosticar_pcap',return_value={'tramas':3,'eapol':0,'truncado':False,'error':None}), \
                 patch.object(main,'confirmar_handshake',return_value={'confirmado':False,'cantidad':0}), \
                 patch.object(main,'crackear') as cr, \
                 contextlib.redirect_stdout(salida):
                self.assertFalse(main.ejecutar_sesion('wlan0',1,1))
            self.assertIn('MAC del dispositivo seleccionado: 11:22:33:44:55:66', salida.getvalue())
            self.assertNotIn('aireplay-ng -0', salida.getvalue())
            self.assertFalse(ruta.exists())
            cr.assert_not_called()

    def test_limpieza_no_borra_captura_manual(self):
        with tempfile.TemporaryDirectory() as t:
            base = Path(t)
            d = base/'capturas_ataque'
            d.mkdir()
            (d/'auditoria_tmp-01.cap').write_bytes(b'1')
            (d/'auditoria_tmp-airodump.log').write_bytes(b'2')
            manual = d/'captura_manual-01.cap'
            manual.write_bytes(b'3')
            with patch.object(main,'BASE',base):
                self.assertEqual(main.limpiar_temporales(),2)
            self.assertTrue(manual.exists())

    def test_csv_omite_canal_invalido(self):
        csv = ('BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n'
               'AA:BB:CC:DD:EE:FF, x, y, -1, 54, WPA2, CCMP, PSK, -60, 2, 0, 0, 0, NULA,\n'
               '11:22:33:44:55:66, x, y, 6, 54, WPA2, CCMP, PSK, -60, 2, 0, 0, 0, BUENA,\n')
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/'escaneo.csv'
            p.write_text(csv)
            redes,_ = _parsear_csv_redes(str(p))
        self.assertEqual(len(redes),1)
        self.assertEqual(redes[0]['essid'],'BUENA')

    def test_interprete_handshake_bssid_especifico(self):
        text = (' #  BSSID              ESSID                     Encryption\n'
                ' 1  AA:BB:CC:DD:EE:FF  RED LAB                   WPA (1 handshake)\n'
                ' 2  11:22:33:44:55:66  OTRO                      WPA (0 handshake)\n')
        self.assertTrue(interpretar_listado(text,'AA:BB:CC:DD:EE:FF')['confirmado'])
        self.assertFalse(interpretar_listado(text,'11:22:33:44:55:66')['confirmado'])

    def test_interprete_cracking_positivo_simulado(self):
        res=interpretar_salida('Read 20 packets.\nKEY FOUND! [ CLAVE_FICTICIA ]\n3/5 keys tested')
        self.assertTrue(res['encontrada'])
        self.assertEqual(res['contrasena'],'CLAVE_FICTICIA')

    def test_interprete_cracking_negativo_simulado(self):
        res=interpretar_salida('Read 20 packets.\nKEY NOT FOUND\n5/5 keys tested')
        self.assertFalse(res['encontrada'])

    def test_pcap_ausente_se_reporta_como_error(self):
        with tempfile.TemporaryDirectory() as t:
            res = diagnosticar_pcap(str(Path(t)/'inexistente.cap'))
            self.assertIsNotNone(res['error'])
            self.assertEqual(res['tramas'], 0)

    def test_monitor_verificacion_tipo_managed(self):
        resultado = SimpleNamespace(returncode=0, stdout='Interface wlan0\n    type managed\n', stderr='')
        with patch('monitor_mode.subprocess.run', return_value=resultado):
            self.assertFalse(verificar_modo_monitor('wlan0'))

    def test_monitor_verificacion_tipo_monitor(self):
        resultado = SimpleNamespace(returncode=0, stdout='Interface wlan0\n    type monitor\n', stderr='')
        with patch('monitor_mode.subprocess.run', return_value=resultado):
            self.assertTrue(verificar_modo_monitor('wlan0'))

    def test_monitor_cambia_nombre_de_interfaz(self):
        with patch('monitor_mode.verificar_modo_monitor', side_effect=[False, RuntimeError('no wlan0'), True]), \
             patch('monitor_mode.subprocess.run', return_value=SimpleNamespace(returncode=0,stdout='',stderr='')), \
             patch('monitor_mode.time.sleep'):
            self.assertEqual(iniciar_modo_monitor('wlan0'), 'wlan0mon')

    def test_captura_referencia_estructural_si_existe(self):
        cap=Path(__file__).with_name('captura_manual-01.cap')
        if not cap.exists():
            self.skipTest('La captura de referencia no forma parte del repositorio')
        tramas, truncado=inspeccion_basica_pcap(cap)
        self.assertEqual(tramas,7149)
        self.assertFalse(truncado)

if __name__=='__main__':
    unittest.main(verbosity=2)

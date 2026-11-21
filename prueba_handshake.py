"""Pruebas offline del detector WPA/WPA2. No usa Wi-Fi ni prueba contraseñas.

Ejecutar: python3 prueba_handshake.py
Opcional: python3 prueba_handshake.py --cap captura_manual-01.cap
"""
import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from handshake import interpretar_listado, confirmar_handshake

BSSID_1 = '8C:5F:AD:59:86:0B'
BSSID_2 = '11:22:33:44:55:66'
SALIDA_CON_HANDSHAKE = '''Reading packets, please wait...
Read 7149 packets.

   #  BSSID              ESSID                     Encryption

   1  8C:5F:AD:59:86:0B  RED-LAB                   WPA (1 handshake)
   2  11:22:33:44:55:66  RED-OTRA                  WPA (0 handshake)

Choosing first network as target.
Please specify a dictionary (option -w).
'''
SALIDA_SIN_HANDSHAKE = '''Reading packets, please wait...
Read 318 packets.

   #  BSSID              ESSID                     Encryption

   1  8C:5F:AD:59:86:0B  RED-LAB                   WPA (0 handshake)

Please specify a dictionary (option -w).
'''


class PruebasDetector(unittest.TestCase):
    def test_caso_positivo(self):
        resultado = interpretar_listado(SALIDA_CON_HANDSHAKE, BSSID_1)
        self.assertTrue(resultado['confirmado'])
        self.assertEqual(resultado['cantidad'], 1)
        self.assertEqual(resultado['estado'], 'confirmado')

    def test_caso_negativo(self):
        resultado = interpretar_listado(SALIDA_SIN_HANDSHAKE, BSSID_1)
        self.assertFalse(resultado['confirmado'])
        self.assertEqual(resultado['cantidad'], 0)

    def test_no_confundir_otro_bssid(self):
        resultado = interpretar_listado(SALIDA_CON_HANDSHAKE, BSSID_2)
        self.assertFalse(resultado['confirmado'])
        self.assertEqual(resultado['cantidad'], 0)

    def test_red_no_encontrada(self):
        resultado = interpretar_listado(SALIDA_CON_HANDSHAKE, 'AA:BB:CC:DD:EE:FF')
        self.assertFalse(resultado['confirmado'])
        self.assertEqual(resultado['estado'], 'red_no_encontrada')

    def test_bssid_invalido(self):
        with self.assertRaises(ValueError):
            interpretar_listado(SALIDA_CON_HANDSHAKE, 'INVALIDO')

    def test_archivo_vacio(self):
        with tempfile.TemporaryDirectory() as carpeta:
            vacio = Path(carpeta) / 'vacio.cap'
            vacio.touch()
            with self.assertRaises(FileNotFoundError):
                confirmar_handshake(vacio)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cap', type=Path, help='PCAP real opcional para comparar con las pruebas simuladas')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PruebasDetector)
    resultado = unittest.TextTestRunner(verbosity=2).run(suite)
    if not resultado.wasSuccessful():
        return 1
    print('\n[OK] Las seis pruebas offline del detector se completaron.')
    if args.cap is not None:
        from ataque import diagnosticar_pcap
        diagnostico = diagnosticar_pcap(str(args.cap))
        evaluacion = confirmar_handshake(args.cap)
        print(f'\nArchivo: {args.cap}')
        print(f'Tramas: {diagnostico["tramas"]} | EAPOL: {diagnostico["eapol"]}')
        print(f'Truncamiento detectado: {diagnostico["truncado"]}')
        print(f'Handshakes reconocidos: {evaluacion["cantidad"]} | Estado: {evaluacion["estado"]}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

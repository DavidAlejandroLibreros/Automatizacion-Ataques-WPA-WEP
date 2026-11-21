"""Prueba de integración de lectura de un PCAP conocido (solo lectura).

No modifica main.py, no captura tráfico, no prueba contraseñas y no guarda
informes. Utiliza los módulos reales ataque.py y handshake.py de Kali.

Uso: python3 prueba_integracion_cap.py
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
CAP = BASE / 'captura_manual-01.cap'
BSSID_ESPERADO = '8C:5F:AD:59:86:0B'


def inspeccion_basica_pcap(ruta: Path) -> tuple[int, bool]:
    """Cuenta registros PCAP clásico sin dependencias externas.

    Retorna (tramas, truncado). Este chequeo NO verifica EAPOL ni handshakes.
    """
    with ruta.open('rb') as f:
        encabezado = f.read(24)
        if len(encabezado) < 24:
            raise ValueError('El PCAP no tiene una cabecera completa')
        magic = encabezado[:4]
        if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
            orden = '<'
        elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
            orden = '>'
        else:
            raise ValueError('El archivo no parece un PCAP clásico')
        tramas = 0
        while True:
            registro = f.read(16)
            if not registro:
                return tramas, False
            if len(registro) < 16:
                return tramas, True
            _, _, longitud, _ = struct.unpack(orden + 'IIII', registro)
            if longitud > 16_777_216:
                raise ValueError('Longitud de registro PCAP inesperada')
            if len(f.read(longitud)) != longitud:
                return tramas, True
            tramas += 1


def main() -> int:
    if not CAP.is_file():
        print(f'[ERROR] No existe {CAP.name} junto al script.')
        return 1
    try:
        total, truncado = inspeccion_basica_pcap(CAP)
        print(f'Archivo: {CAP.name}')
        print(f'Registros PCAP: {total}')
        print(f'PCAP truncado (lectura estructural): {"Sí" if truncado else "No"}')
        if truncado or total == 0:
            print('[ERROR] Captura incompleta o vacía.')
            return 1
        from ataque import diagnosticar_pcap
        from handshake import confirmar_handshake

        diagnostico = diagnosticar_pcap(str(CAP))
        if diagnostico.get('error'):
            print(f'[ERROR] TShark: {diagnostico["error"]}')
            return 1
        print(f'Tramas según TShark: {diagnostico.get("tramas")}')
        print(f'Mensajes EAPOL: {diagnostico.get("eapol")}')
        if diagnostico.get('truncado'):
            print('[ERROR] TShark detectó truncamiento.')
            return 1
        verificacion = confirmar_handshake(CAP, BSSID_ESPERADO)
        print(f'Handshakes del BSSID de referencia: {verificacion.get("cantidad", 0)}')
        print(f'Estado: {verificacion.get("estado")}')
        ok = bool(verificacion.get('confirmado')) and diagnostico.get('eapol', 0) > 0
        print('[OK] Integración de lectura y detección validada.' if ok else
              '[AVISO] No se pudo confirmar el handshake de referencia.')
        return 0 if ok else 1
    except (OSError, RuntimeError, ValueError) as exc:
        print(f'[ERROR] {exc}')
        return 1


if __name__ == '__main__':
    sys.exit(main())

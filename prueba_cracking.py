"""Pruebas offline: no ejecutan aircrack-ng ni acceden a la red."""
from cracking import interpretar_salida

sin_coincidencia = "Read 1,234 packets.\n456/500 keys tested\nKEY NOT FOUND"
resultado = interpretar_salida(sin_coincidencia)
assert resultado['encontrada'] is False
assert resultado['paquetes_leidos'] == 1234
assert resultado['claves_probadas'] == 456

con_coincidencia = "Read 28 packets.\n3/5 keys tested\nKEY FOUND! [ clave_de_ejemplo ]"
resultado = interpretar_salida(con_coincidencia)
assert resultado['encontrada'] is True
assert resultado['contrasena'] == 'clave_de_ejemplo'
assert resultado['claves_probadas'] == 3

vacio = interpretar_salida('No valid handshake')
assert vacio['encontrada'] is False
assert vacio['claves_probadas'] is None
assert vacio['paquetes_leidos'] is None
print('[OK] Las tres pruebas offline de cracking.py se completaron.')

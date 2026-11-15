# main.py
from monitor_mode import iniciar_modo_monitor
from escaneo import escanear_redes


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


if __name__ == "__main__":
    nombre_interfaz = input("Escribe el nombre de tu interfaz Wi-Fi (ej. wlan0): ")
    interfaz_monitor = iniciar_modo_monitor(nombre_interfaz)
    redes, clientes = escanear_redes(interfaz_monitor)

    red_elegida = elegir_red(redes)
    cliente_elegido = elegir_cliente(clientes, red_elegida["bssid"])

    print(f"\nObjetivo: red '{red_elegida['essid']}' ({red_elegida['bssid']}), cliente {cliente_elegido['mac_cliente']}")
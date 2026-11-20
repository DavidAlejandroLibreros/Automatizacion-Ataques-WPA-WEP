import subprocess
import time
import csv

def escanear_redes(interfaz_monitor: str, duracion_segundos: int = 15, archivo_salida: str = "escaneo"):
    
    # Comando a ejecutar en la terminal
    
        comando = [
        "sudo", "airodump-ng",
        interfaz_monitor,
        "--output-format", "csv",
        "-w", archivo_salida
    ]
        
    # Ejecutamos el comando en un subproceso
    
        proceso = subprocess.Popen(
        comando,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
        
    # Pausamos la ejecución de Python para que se escaneen las redes tranquilamente
    
        time.sleep(duracion_segundos)
        
        proceso.terminate()
        proceso.wait()
        
        nombre_csv = f"{archivo_salida}-01.csv"
        return _parsear_csv_redes(nombre_csv)
    
    
def _parsear_csv_redes(ruta_csv: str) -> list:
    
        # Lee el CSV generado por el comando y separa las tablas de redes y clientes.
        
        redes = []
        clientes = []
        
        with open(ruta_csv, "r", encoding="utf-8", errors="replace") as archivo:
            contenido = archivo.read()
        
        tabla_redes, tabla_clientes = contenido.split("\n\n")[:2]
        
        lector_redes = csv.DictReader(tabla_redes.splitlines())
        for fila in lector_redes:
            redes.append({
                "bssid": fila["BSSID"].strip(),
                "canal": fila[" channel"].strip(),
                "cifrado": fila[" Privacy"].strip(),
                "essid": fila[" ESSID"].strip(),
            })

        lector_clientes = csv.DictReader(tabla_clientes.splitlines())
        for fila in lector_clientes:
            clientes.append({
                "mac_cliente": fila["Station MAC"].strip(),
                "bssid_conectado": fila[" BSSID"].strip(),
            })

        return redes, clientes
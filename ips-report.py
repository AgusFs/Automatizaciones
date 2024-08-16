# Desarrollado por Grabriel Darqui - Andre Cueva - Agustín Fernández
# última actualización 28/03/2023



import sys, os, time
import argparse , csv, requests
import yaml


#--------------------------------------------------------------------------------------------------------------------#
# Obtener archivo de configuracion

def get_config(file_config) -> dict:
    if file_config and os.path.exists(file_config):
        with open (file=file_config, mode="r") as file_config:
            #reader = file_config.read
            config = yaml.safe_load(file_config)
    else:
         sys.exit("El archivo de configuracion mencionado no existe\n")

    return (config)

#--------------------------------------------------------------------------------------------------------------------#
# Traer linea de configuracion en base a un parámetro

def get_content (config, value: str):
    line_config = config[value]
    return (line_config)

#--------------------------------------------------------------------------------------------------------------------#
# Funcion para procesar los archivos CSV y devuelve una lista

def parsear_csv(csv_file: str, isdebug: bool, exit=False) -> list:
    lst = []
    """Verifico si el archivo existe y proceso"""
    if (isdebug==True):
        print("Se va a procesar el archivo: \"" + os.path.basename(csv_file)+ "\"")
    if csv_file and os.path.exists(csv_file):
        with open(csv_file, "r") as f:
            reader = csv.DictReader(f)
            lst = [dct for dct in reader]
    else:
        print("El archivo mencionado en el parámetro no existe")
        try:
            if (csv_file and exit==False):
                with open(csv_file, "w") as f:
                    reader = csv.DictReader(f)
        except:
            print("Revisar comentarios linea 48")

    
    if (len(lst) <= 1):
        if (isdebug == True):
            print("El archivo " + os.path.basename(csv_file) +" está vacío")
        if (exit == True):
            sys.exit("No hay nada para analizar\n")

    else:
        pass    
    
    return lst


#--------------------------------------------------------------------------------------------------------------------#
# Obtiene exclusivamente las ips unicas (una por coincidencia)

def get_unique_ips(ips: list) -> list:
    """Genera una lista de diccionarios con estadísticas de IPs,
    con formato {"addr": "127.0.0.1", "sid": 1, "count": 1}
    Las IPs son únicas y están ordenadas por cantidad de ocurrencias.
    """
    #que hacemos con las reglas que contienen ANY en el addr?? AGUSTIN
    ips_sorted = [dct for dct in ips if dct["sid"] == "any"]
    ips_sorted.sort(key=lambda x: int(x["count"]), reverse=True)

    ips_unique = [ips_sorted[0]]
    for i in range(1, len(ips_sorted)):
        if ips_sorted[i - 1] != ips_sorted[i]:
            ips_unique.append(ips_sorted[i])
        else:
            ips_unique[-1]["count"] += ips_sorted[i]["count"]

    return ips_unique

#--------------------------------------------------------------------------------------------------------------------#
# Funcion para depurar ips, compara listas y las no coincidencias las coloca en una lista

def deputate_ips(ips: list, filtro: list, filename, isdebug:bool) -> list:
    """depurar ips"""
    if (len(filtro) != 0):
        # lista plana de strings con las IPs ya evaluadas
        ips_analyzed = [dct["addr"] for dct in filtro]

        #ips_rated = [dct for dct in ips if dct["addr"] in rated_ip_list]
        depurate_ips = [dct for dct in ips if dct["addr"] not in ips_analyzed]
        return depurate_ips
    else:
        if (isdebug == True):
            print ("No se realizar la comparacion con "+os.path.basename(filename)+" (len: " + str(len(filtro)) +")\n" )
        
        return ips

#--------------------------------------------------------------------------------------------------------------------#
# funcion para obtener la reputacion de una IP a través de la API de Virustotal

def get_ip_reputation(ip: str, apikey: str) -> dict:
    """Realiza una consulta a la API de VirusTotal de la reputación de la IP ingresada.
    """
    try:
        url = "https://www.virustotal.com/api/v3/ip_addresses/"
        headers = { "x-apikey" : str(apikey) }
        response = requests.get(url + ip, headers=headers)
        analysis = response.json()["data"]["attributes"]["last_analysis_stats"]
        analysis["addr"] = ip
        #print("analysis:\n" + str(analysis) + "\n")
        return analysis
    
    except:
        sys.exit("\nPor favor revisar conexión con virustotal..\n")

#--------------------------------------------------------------------------------------------------------------------#
# Funcion para determinar si una ip es malisiosa

def is_malisious (ip: dict):
    if(int(ip["malicious"]) != 0 or int(ip["suspicious"]) != 0):
        print("La ip: "+ip["addr"]+" es MALICIOSA, revisar!!")

    else:
        print("La ip: "+ip["addr"]+ " no es maliciosa\n")
    
        ## si es maliciosa pegarlo en txt de <ips maliciosas
        ## si no es maliciosa pegarlo en txt ips analizadas y ips no malici

    return int(ip["malicious"]) != 0 or int(ip["suspicious"]) != 0

#--------------------------------------------------------------------------------------------------------------------#
# Funcion para escribir en los archivos

def write_file(NombreArchivo, header, resultado: dict):
    if (os.path.exists(NombreArchivo)):
        #print ("El archivo existe, se omite creación")
        with open (file=NombreArchivo, mode='a+') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header,lineterminator="\n")
            writer.writerow(resultado)
    else:
        #print ("Creando archivo")
        with open (file=NombreArchivo, mode='w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=header, lineterminator="\n")
            #print(header) # imprime correctamente el header
            writer.writeheader() # Escribe el header pero no realiza un append
            writer.writerow(resultado)

#--------------------------------------------------------------------------------------------------------------------#
# Funcion de cuenta regresiva por consola

def countdown(t):
    
    while t:
        mins, secs = divmod(t, 60)
        timer = '{:02d}:{:02d}'.format(mins, secs)
        print("Delay: ",timer, end="\r")
        time.sleep(1)
        t -= 1

#######################################################################
### reprocesar historico ###
#FUNCION DEL SCRIPT ANTERIOR NO CUSTOMIZADA
"""
def reprocesar_historico(ip: dict, in_rows: list, analysis_rows: list, malicious_rows: list, non_malicious_rows: list) -> None:
    # Funcion sin desarrollar, la idea es que actualice todo el hostórico con los nuevos resultados.
    # Puede suceder que una ip cambie de estado, esto se deberia ejecutar cada 3-6 meses aprox, definir con gonza.

    # buscar el resultado de reputación de la IP en la lista de diccionarios de análisis
    analysis = next((dct for dct in analysis_rows if dct["addr"] == ip["addr"]), None)

    # elegir archivo a actualizar según la reputación de la IP
    rows_to_update = []
    if is_malicious(analysis):
        rows_to_update = malicious_rows
    else:
        rows_to_update = non_malicious_rows

    # buscar filas del CSV de entrada con la IP actual (filas nuevas)
    # las filas "sid == any" no se agregan al archivo
    new_rows = [
            dct for dct in in_rows if
            dct["addr"] == ip["addr"] and dct["sid"] != "any"
    ]

    # buscar filas del archivo con la IP actual (filas viejas)
    old_rows = []
    if rows_to_update:
        old_rows = [
                dct for dct in rows_to_update if
                dct["addr"] == ip["addr"]
        ]

    # recorrer filas nuevas
    for new_row in new_rows:

        # buscar fila vieja con la misma IP y SID que la fila nueva
        old_row = None
        if old_rows:
            old_row = find_row(old_rows, addr=new_row["addr"], sid=new_row["sid"])

        # si existe, actualizar el número de ocurrencias registradas
        if old_row:
            old_row["count"] = str(int(old_row["count"]) + int(new_row["count"]))

        # sino, agregar la fila nueva
        else:
            rows_to_update.append(new_row)

        # buscar fila "addr == any" del CSV de IPs no maliciosas para cada SID de esta IP
        # si existe, actualizar el número de ocurrencias, o sino, agregar una fila nueva
        update_row_count(
                rows_to_update, addr="any", sid=new_row["sid"], count=new_row["count"]
        )
"""

#--------------------------------------------------------------------------------------------------------------------#
                    ############################ Bloque principal #########################
#--------------------------------------------------------------------------------------------------------------------#

def main (input: str, exceptions: str, historique: str, file_config, isdebug: bool, delay: int):

    ## Bloque de parámetros y variables ##
    config = get_config(file_config)

    file_analysys = input
    apikey_virustotal =     get_content(config=config, value="api.key_virustotal")

    
    # Si no me enviaron el archivo por parámetro, lo tomo del archivo de configuracion (yml)
    if (exceptions==""):
        file_exceptions =   get_content(config=config, value="file.exceptions")
    else:
        file_exceptions = exceptions

    print(historique)
    if (historique==""):
        file_historique =   get_content(config=config, value="file.historique")
    else:
        file_historique = historique

    NombreArchivo = "Reputation-analysis-ips_" + time.strftime("%d-%m-%Y-(%H%M%S)") + ".csv"
    IpsMaliciosas = "IpsMaliciosas_analisis_"  + time.strftime("%d-%m-%Y-(%H%M%S)") + ".csv"
    header = ("addr", "harmless", "malicious", "suspicious", "undetected", "timeout")
    
   
    
    ## procesar inputs CSVs ##

    brutelist_ips_analisis = parsear_csv(csv_file=input, exit=True, isdebug=isdebug)

    brutelist_historique   = parsear_csv(csv_file=file_historique, isdebug=isdebug)

    brutelist_exceptions   = parsear_csv(csv_file=file_exceptions, isdebug=isdebug)

    # obtener ips unicas y compararlas con el historico, las ips no analizadas van a la variable de analisis
    analyze_ips = get_unique_ips(brutelist_ips_analisis)
    analyze_ips = deputate_ips(ips=analyze_ips, filtro=brutelist_historique, filename=file_historique, isdebug=isdebug)
    analyze_ips = deputate_ips(ips=analyze_ips, filtro=brutelist_exceptions, filename=file_exceptions, isdebug=isdebug)



    if (isdebug == True and config):
        print   (
                    "Api.key de virustotal: "       + apikey_virustotal     + "\n" +
                    "Archivo de analisis: "         + file_analysys         + "\n" +
                    "Archivo de configuracion: "    + file_config           + "\n" +  
                    "Archivo de excepciones: "      + file_exceptions       + "\n" +
                    "Archivo del historico: "       + file_historique       + "\n" +
                    "tiempo de espera entre consultas " + str(delay) + " segundos \n" + ""
                )    

    ## Bloque de control, evitar un fallo por un hostorico sin header. 

    file = open(file=file_historique,mode="r")
    lines =file.readlines()
    #print(file_historique)
    if (len(lines)==0):
        if(isdebug==True):
            print("archivo vacio, se incorpora header")
        with open (file=file_historique, mode='w') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header, lineterminator="\n")
                #print(header) # imprime correctamente el header
                writer.writeheader() # Escribe el header pero no realiza un append

    #Si el archivo existe pero no tiene header, ejecuto:
    else:
        primera_linea=lines[0].strip()
        if (primera_linea==",".join(header)):
            pass
        else:
            with open (file=file_historique, mode='w') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header, lineterminator="\n")
                #print(header) # imprime correctamente el header
                writer.writeheader() # Escribe el header pero no realiza un append


    ## Bloque de consulta y escritura en los archivos  ##
    if (len(analyze_ips)>0):
        """"Generar archivo donde volcar el analisis (si y solo si tengo ips a analizar)"""
        #Obtener solo el campo ip para enviar a virustotal
        only_ips = [dct["addr"] for dct in analyze_ips]

        # Envío la primera ip analisis
        print ("Enviar a virustotal: ", only_ips[0]  +"\n")
        temporal = get_ip_reputation(only_ips[0], apikey=apikey_virustotal)
        print (temporal, "\n")
        write_file(file_historique,header, temporal)
        write_file (NombreArchivo, header, temporal)


        ## Bloque para incorporar el envio de alertas por smtp

        if is_malisious(temporal) == True:
            write_file (IpsMaliciosas, header, temporal)
        else:
            pass

        countdown (int(delay))


        # Bucle para enviar toda las ips a analizar
        for i in range(1, len(analyze_ips)):
            #print("Comienzo de for")
            #print (i," - ",analyze_ips[i])
            print ("Enviar a virustotal: ",only_ips[i] + "\n")
            # variable temporal para almacenar el resultado mientras de escribe en los registros
            temporal = get_ip_reputation(only_ips[i], apikey=apikey_virustotal)
            print (temporal, "\n")
            write_file(file_historique, header, temporal)
            write_file (NombreArchivo, header, temporal)
            if is_malisious(temporal) == True:
                write_file (IpsMaliciosas, header, temporal)
                
            countdown (int(delay))


#--------------------------------------------------------------------------------------------------------------------#
#--------------------------------------------------------------------------------------------------------------------#
 
if __name__=="__main__":
        """Definir objeto parser"""
        parseador = argparse.ArgumentParser("config", description="Archivo de configuracion .yml")
        parseador.add_argument("-i", "--input", required=True)
        parseador.add_argument("-j", "--historique", required=False, default="")
        parseador.add_argument("-e", "--exceptions", required=False, default="")
        parseador.add_argument("-c", "--config", required=False, default=".\config.yml")
        parseador.add_argument("-d", "--debug", required=False, default=False, action='store_true')
        parseador.add_argument("-t", "--delay", required=False, default=15)
        args = parseador.parse_args()

        main(input=args.input, historique=args.historique, exceptions=args.exceptions ,file_config=args.config, isdebug=args.debug, delay=args.delay)




# Solcito input de configuracion
# Envio input a la funcion get_config
# Analizo la existencia del archivo
    # Si si, abro y retorno config
    # Si no, emito mensaje y finalizo
# Si debug = true y el archivo de configuracion existe
    # imprimo resultado de variables



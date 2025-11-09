

from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KBT
KBT = open("KBT.bin", "rb").read()

# Paso 1) B->T: KBT(Bob, Nb) en AES-GCM
#######################################

# Crear el socket de conexion con T (5551)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5551)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Bob")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("B -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KBT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 2) T->B: KBT(K1, K2, Nb) en AES-GCM
##########################################

# Recibir los tres componentes del mensaje del TTP
cifrado_TB = socket.recibir()
mac_TB = socket.recibir()
nonce_TB = socket.recibir()

datos_descifrados_TB = funciones_aes.descifrarAES_GCM(KBT,nonce_TB, cifrado_TB, mac_TB)

if not datos_descifrados_TB:
  print("Error: MAC incorrecto, mensaje no autentico")
  socket.cerrar()

# Decodificar JSON
json_TB = datos_descifrados_TB.decode("utf-8")
print("T->B (descifrado): " + json_TB)
msg_TB = json.loads(json_TB)

# Extraer K1, K2 y el nonce (y convertirlos de hexadecimal a bytes)
k1_hex, k2_hex, nb_hex = msg_TB
K1 = bytearray.fromhex(k1_hex)
K2 = bytearray.fromhex(k2_hex)
nb_recibido = bytearray.fromhex(nb_hex)

# Verificacion de nonce (el que enviamos y el que recibimos)
if nb_recibido != t_n_origen:
  print("Error: Nonces no coinciden")
  socket.cerrar()
else:
  print("Nonce verificado correctamente")

# Cerramos el socket entre B y T, no lo utilizaremos mas
socket.cerrar() 

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# Crear el socket de conexion con A (5553)
print("Esperando a Alice")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket.escuchar()

nonce_ctr = socket.recibir()
cifrado_AB = socket.recibir()
hmac_recibido = socket.recibir()

# Verificar MAC

hmac_calculado = HMAC.new(K2, cifrado_AB, SHA256).digest()

if hmac_calculado != hmac_recibido:
  print("Error: Manipulacion de mensaje")
  socket.cerrar()
else:
  print("HMAC verificado")

# Iniciar descifrado CTR (Con K1 y nonce recibido)
aes_descifrado = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_ctr)

# Descifrar los datos
datos_descifrados = funciones_aes.descifrarAES_CTR(aes_descifrado, cifrado_AB)
mensaje_claro = datos_descifrados.decode("utf-8")
print("A->B (descifrado): " + mensaje_claro)

# (Aquí debe estar el código del Paso 5, asegurándote de que
#  guardaste el objeto 'aes_descifrado' y el 'socket' de Alice)

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################

print("Enviando 'Torres' a Alice...")
apellido = "Torres" 
apellido_bytes = apellido.encode("utf-8")

# Cifrar el apellido usando el MISMO motor AES del Paso 5
cifrado_BA = funciones_aes.descifrarAES_CTR(aes_descifrado, apellido_bytes)

# Calcular el HMAC del texto CIFRADO usando K2
hmac_BA = HMAC.new(K2, cifrado_BA, SHA256).digest()

# Enviar (No enviamos nonce, ya está sincronizado desde el Paso 5)
socket.enviar(cifrado_BA)
socket.enviar(hmac_BA)
print("Apellido enviado.")

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################
print("Esperando 'END' de Alice...")

# Recibir el mensaje 'END'
cifrado_AB_end = socket.recibir()
hmac_AB_end_recibido = socket.recibir()

# Verificar el HMAC
hmac_AB_end_calculado = HMAC.new(K2, cifrado_AB_end, SHA256).digest()

if hmac_AB_end_calculado != hmac_AB_end_recibido:
    print("Error: HMAC final no válido.")
    socket.cerrar()
else:
  print("HMAC de Alice (END) verificado.")

# Descifrar el mensaje usando el MISMO motor AES
datos_descifrados_end = funciones_aes.descifrarAES_CTR(aes_descifrado, cifrado_AB_end)
mensaje_end = datos_descifrados_end.decode("utf-8")

print("A->B (descifrado): " + mensaje_end)

if mensaje_end == "END":
    print("Protocolo finalizado con éxito.")

socket.cerrar()
print("Socket con Alice cerrado.")

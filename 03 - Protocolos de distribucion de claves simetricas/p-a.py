
from Crypto.Hash import SHA256, HMAC
import base64
import json
import sys
from socket_class import SOCKET_SIMPLE_TCP
import funciones_aes
from Crypto.Random import get_random_bytes

# Paso 0: Inicializacion
########################

# Lee clave KAT

KAT = open("KAT.bin", "rb").read()

# Paso 3) A->T: KAT(Alice, Na) en AES-GCM
#########################################

# Crear el socket de conexion con T (5552 porque 5551 ya lo usa Bob)
print("Creando conexion con T...")
socket = SOCKET_SIMPLE_TCP('127.0.0.1', 5552)
socket.conectar()

# Crea los campos del mensaje
t_n_origen = get_random_bytes(16)

# Codifica el contenido (los campos binarios en una cadena) y contruyo el mensaje JSON
msg_TE = []
msg_TE.append("Alice")
msg_TE.append(t_n_origen.hex())
json_ET = json.dumps(msg_TE)
print("A -> T (descifrado): " + json_ET)

# Cifra los datos con AES GCM
aes_engine = funciones_aes.iniciarAES_GCM(KAT)
cifrado, cifrado_mac, cifrado_nonce = funciones_aes.cifrarAES_GCM(aes_engine,json_ET.encode("utf-8"))

# Envia los datos
socket.enviar(cifrado)
socket.enviar(cifrado_mac)
socket.enviar(cifrado_nonce)

# Paso 4) T->A: KAT(K1, K2, Na) en AES-GCM
##########################################

# Recibir los tres componentes del mensaje del TTP
cifrado_TA = socket.recibir()
mac_TA = socket.recibir()
nonce_TA = socket.recibir()

datos_descifrados_TA = funciones_aes.descifrarAES_GCM(KAT,nonce_TA, cifrado_TA, mac_TA)

if not datos_descifrados_TA:
  print("Error: MAC incorrecto, mensaje no autentico")
  socket.cerrar()

# Decodificar JSON
json_TA = datos_descifrados_TA.decode("utf-8")
print("T->A (descifrado): " + json_TA)
msg_TA = json.loads(json_TA)

# Extraer K1, K2 y el nonce (y convertirlos de hexadecimal a bytes)
k1_hex, k2_hex, na_hex = msg_TA
K1 = bytearray.fromhex(k1_hex)
K2 = bytearray.fromhex(k2_hex)
na_recibido = bytearray.fromhex(na_hex)

# Verificacion de nonce (el que enviamos y el que recibimos)
if na_recibido != t_n_origen:
  print("Error: Nonces no coinciden")
  socket.cerrar()
else:
  print("Nonce verificado correctamente")

socket.cerrar()

# Paso 5) A->B: KAB(Nombre) en AES-CTR con HMAC
###############################################

# Conectarse a Bob
print("Conectando con Bob...")
socket_B = SOCKET_SIMPLE_TCP('127.0.0.1', 5553)
socket_B.conectar()

#  Iniciar el motor de cifrado AES-CTR con K1
aes_cifrado, nonce_ctr = funciones_aes.iniciarAES_CTR_cifrado(K1)

#  Cifrar el mensaje 
nombre = "Pablo"
cifrado_AB = funciones_aes.cifrarAES_CTR(aes_cifrado, nombre.encode("utf-8"))

# Calcular HMAC del cifrado usando K2
hmac_enviado = HMAC.new(K2,cifrado_AB, SHA256).digest()

# Enviar a Bob
socket_B.enviar(nonce_ctr)      
socket_B.enviar(cifrado_AB)    
socket_B.enviar(hmac_enviado)  
print("Mensaje enviado a Bob.")

# Paso 6) B->A: KAB(Apellido) en AES-CTR con HMAC
#################################################
print("Esperando 'Apellido' de Bob...")

# Recibir apellido
cifrado_BA = socket_B.recibir()
hmac_BA_recibido = socket_B.recibir()

# Verificar el HMAC
hmac_BA_calculado = HMAC.new(K2, cifrado_BA, SHA256).digest()

if hmac_BA_calculado != hmac_BA_recibido:
    print("Error: HMAC de Bob no válido.")
    socket_B.cerrar()
    sys.exit()

print("HMAC de Bob verificado.")

# Descifrar el mensaje usando el MISMO motor AES del Paso 5
datos_descifrados_BA = funciones_aes.descifrarAES_CTR(aes_cifrado, cifrado_BA)
apellido = datos_descifrados_BA.decode("utf-8")

print("B->A (descifrado): " + apellido)

# Paso 7) A->B: KAB(END) en AES-CTR con HMAC
############################################

print("Enviando 'END' a Bob...")
mensaje_end = "END"
mensaje_end_bytes = mensaje_end.encode("utf-8")

# Cifrar el mensaje 'END' usando el MISMO motor AES
cifrado_AB_end = funciones_aes.descifrarAES_CTR(aes_cifrado, mensaje_end_bytes)

# Calcular el HMAC del texto CIFRADO usando K2
hmac_AB_end = HMAC.new(K2, cifrado_AB_end, SHA256).digest()

# Enviar
socket_B.enviar(cifrado_AB_end)
socket_B.enviar(hmac_AB_end)
print("Mensaje 'END' enviado.")

#  Cerrar la conexión
socket_B.cerrar()
print("Socket con Bob cerrado.")

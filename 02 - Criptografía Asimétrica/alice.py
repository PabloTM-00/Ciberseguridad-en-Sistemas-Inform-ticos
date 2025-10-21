import funciones_rsa
import funciones_aes
from socket_class import SOCKET_SIMPLE_TCP

PASSWORD_ALICE = "alice123"

#Datos Socket
HOST = '127.0.0.1'
PORT = 5555

#Cargar clave privada alice y clave publica bob
try:
    key_privada_alice = funciones_rsa.cargar_RSAKey_Privada("alice_privada.pem", PASSWORD_ALICE)
    key_publica_bob = funciones_rsa.cargar_RSAKey_Publica("bob_publica.pem")
except FileNotFoundError:
    print("Error")
    exit()

#Usar funcion de funciones_aes que genera 16 bytes aleatorios
K1 = funciones_aes.crear_AESKey()

#Cifrarlo con la clave publica de bob
K1_cifrado = funciones_rsa.cifrarRSA_OAEP(K1, key_publica_bob)

#Firmarlo utilizando la clave privada de alice 
firma_K1 = funciones_rsa.firmarRSA_PSS(K1, key_privada_alice)

#Conexion
socket_cliente = SOCKET_SIMPLE_TCP(HOST, PORT)
socket_cliente.conectar()

#Enviar cifrado y firma
socket_cliente.enviar(K1_cifrado)
socket_cliente.enviar(firma_K1)

#Recibir de bob
try:
    nonce_bob = socket_cliente.recibir() 
    cifrado_aes_bob = socket_cliente.recibir() 
    firma_bob = socket_cliente.recibir() 

    #Descifrar el mensaje de Bob 
    #Usar K1 generada antes y el nonce enviado de bob
    aes_descifrado_bob = funciones_aes.iniciarAES_CTR_descifrado(K1, nonce_bob)
    datos_bob_claro = funciones_aes.descifrarAES_CTR(aes_descifrado_bob, cifrado_aes_bob)
    mensaje_bob = datos_bob_claro.decode('utf-8')

    #comprobar firma de bob 
    es_valida = funciones_rsa.comprobarRSA_PSS(datos_bob_claro, firma_bob, key_publica_bob)
    
    if es_valida:
        print(f"VALID: '{mensaje_bob}'")
    else:
        print("INVALID")

    if es_valida:
        mensaje_alice = "Hola Bob"
        datos_alice = mensaje_alice.encode('utf-8')

        aes_cifrado_alice, nonce_alice = funciones_aes.iniciarAES_CTR_cifrado(K1)
        
        #cifrar mensaje
        cifrado_aes_alice = funciones_aes.cifrarAES_CTR(aes_cifrado_alice, datos_alice)
        
        firma_alice = funciones_rsa.firmarRSA_PSS(datos_alice, key_privada_alice)

        socket_cliente.enviar(nonce_alice)
        socket_cliente.enviar(cifrado_aes_alice)
        socket_cliente.enviar(firma_alice)

except Exception as e:
    print(f"Error durante conexion: {e}")

socket_cliente.cerrar() 

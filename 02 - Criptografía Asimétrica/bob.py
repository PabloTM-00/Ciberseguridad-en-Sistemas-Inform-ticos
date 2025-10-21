import funciones_rsa
import funciones_aes
from socket_class import SOCKET_SIMPLE_TCP

PASSWORD_BOB = "bob456"

#Datos Socket
HOST = '127.0.0.1'
PORT = 5555

#cargar clave privada de bob y clave publica de alice
try:
    key_privada_bob = funciones_rsa.cargar_RSAKey_Privada("bob_privada.pem", PASSWORD_BOB)
    key_publica_alice = funciones_rsa.cargar_RSAKey_Publica("alice_publica.pem")
except FileNotFoundError:
    print("Error")
    exit()

#Iniciar sockey y escucha
socket_servidor = SOCKET_SIMPLE_TCP(HOST, PORT)
socket_servidor.escuchar()

try:
    #Recibir K1 cifrado y  firma
    K1_cifrado = socket_servidor.recibir()
    firma_K1 = socket_servidor.recibir()

    K1_descifrado = funciones_rsa.descifrarRSA_OAEP(K1_cifrado, key_privada_bob) 
    
    #Comprobar firma de K1 utilizando la clave publica de alice
    es_valida_K1 = funciones_rsa.comprobarRSA_PSS(K1_descifrado, firma_K1, key_publica_alice) 

    if es_valida_K1:
        print("VALID")
        #Mostrar clave K1 en un formato legible como hex
        print(f"K1 (hex): {K1_descifrado.hex()}") 
    else:
        print("INVALID")
        socket_servidor.cerrar()
        exit()
    
    if es_valida_K1:
        mensaje_bob = "Hola Alice"
        datos_bob = mensaje_bob.encode('utf-8')

        #Iniciar cifrado AES CTR con K1 
        aes_cifrado_bob, nonce_bob = funciones_aes.iniciarAES_CTR_cifrado(K1_descifrado)
        
        #Cifrar  mensaje
        cifrado_aes_bob = funciones_aes.cifrarAES_CTR(aes_cifrado_bob, datos_bob)
        
        #Firmar el mensaje con la clave privada de Bob 
        firma_bob = funciones_rsa.firmarRSA_PSS(datos_bob, key_privada_bob)

        #Enviar nonce, cifrado y firma 
        socket_servidor.enviar(nonce_bob)
        socket_servidor.enviar(cifrado_aes_bob)
        socket_servidor.enviar(firma_bob)

    nonce_alice = socket_servidor.recibir()
    cifrado_aes_alice = socket_servidor.recibir()
    firma_alice = socket_servidor.recibir()

    #Descifrar mensaje de Alice
    aes_descifrado_alice = funciones_aes.iniciarAES_CTR_descifrado(K1_descifrado, nonce_alice)
    datos_alice_claro = funciones_aes.descifrarAES_CTR(aes_descifrado_alice, cifrado_aes_alice)
    mensaje_alice = datos_alice_claro.decode('utf-8')

    #Comprobar firma de Alice
    es_valida_alice = funciones_rsa.comprobarRSA_PSS(datos_alice_claro, firma_alice, key_publica_alice)
    
    if es_valida_alice:
        print(f"VALID: '{mensaje_alice}'") # 
    else:
        print("INVALID")

except Exception as e:
    print(f"ERROR: {e}")

socket_servidor.cerrar()

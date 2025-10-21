import funciones_rsa

#Alice

password_alice = "alice123"
key_alice = funciones_rsa.crear_RSAKey() 
funciones_rsa.guardar_RSAKey_Privada("alice_privada.pem", key_alice, password_alice) #Alice Private Key
funciones_rsa.guardar_RSAKey_Publica("alice_publica.pem", key_alice) #Alice Public Key

#Bob

password_bob = "bob456"
key_bob = funciones_rsa.crear_RSAKey()  
funciones_rsa.guardar_RSAKey_Privada("bob_privada.pem", key_bob, password_bob) #Bob Private Key
funciones_rsa.guardar_RSAKey_Publica("bob_publica.pem", key_bob) #Bob Public Key

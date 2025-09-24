def cifradoCesar(cadena, desplazamiento):
    """Cifrado Cesar generalizado para mayúsculas y minúsculas"""
    resultado = ''
    i = 0
    while i < len(cadena):
        orden = ord(cadena[i])
        ordenCifrado = 0

        if 65 <= orden <= 90:   # MAYÚSCULAS
            ordenCifrado = ((orden - 65 + desplazamiento) % 26) + 65
        elif 97 <= orden <= 122:  # minúsculas
            ordenCifrado = ((orden - 97 + desplazamiento) % 26) + 97
        else:  # otros caracteres
            ordenCifrado = orden

        resultado += chr(ordenCifrado)
        i += 1

    return resultado

def descifradoCesar(cadena, desplazamiento):
    """Descifrado Cesar generalizado para mayúsculas y minúsculas"""
    resultado = ''
    i = 0
    while i < len(cadena):
        orden = ord(cadena[i])
        ordenDescifrado = 0

        if 65 <= orden <= 90:   # MAYÚSCULAS
            ordenDescifrado = ((orden - 65 - desplazamiento) % 26) + 65
        elif 97 <= orden <= 122:  # minúsculas
            ordenDescifrado = ((orden - 97 - desplazamiento) % 26) + 97
        else:  # otros caracteres
            ordenDescifrado = orden

        resultado += chr(ordenDescifrado)
        i += 1

    return resultado
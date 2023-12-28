#!/usr/bin/python3

from guizero import App, Text, TextBox, PushButton, Box, Combo, CheckBox
import ciphers
import utils
from tkinter import filedialog


def actualizar_interfaz():
    opcion = seleccion_conversion.value
    clave_texto.enabled = opcion in utils.cifrados_con_clave
    modo_descifrado.enabled = opcion not in utils.cifrados_hash


def convertir():
    texto_original = texto_entrada.value
    opcion = seleccion_conversion.value
    clave = clave_texto.value if clave_texto.enabled else None
    es_descifrado = modo_descifrado.value and modo_descifrado.enabled

    try:
        texto_convertido = ciphers.convertir_texto(
            texto_original, opcion, clave, es_descifrado
        )
    except Exception as e:
        texto_convertido = "Error: " + str(e)

    texto_salida.value = texto_convertido


def cargar_archivo():
    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            with open(file_path, "r") as file:
                content = file.read()
                texto_entrada.value = content
        except Exception as e:
            print(f"Error al abrir el archivo: {e}")


app = App(title="Convertidor de Texto by NCH", width=500, height=470)

Box(app, height=10)
Text(app, text="Ingresa tu texto aquí:")
texto_entrada = TextBox(app, width=50, height=5, multiline=True, scrollbar=True)

Box(app, height=10)
PushButton(app, text="Cargar Archivo", command=cargar_archivo)
Box(app, height=10)

Text(app, text="Selecciona el tipo de conversión:")
seleccion_conversion = Combo(
    app,
    options=utils.coders,
    selected="Seleccionar",
    width=20,
    command=actualizar_interfaz,
)

Box(app, height=10)

modo_descifrado = CheckBox(
    app, text="Modo Descifrado/Unescape", command=actualizar_interfaz
)
modo_descifrado.enabled = False

Box(app, height=10)

Text(app, text="Clave para XOR/RC4/RC2/DES/3DES/AES:")
clave_texto = TextBox(app, width=50, enabled=False)

Box(app, height=10)

PushButton(app, text="Convertir", command=convertir)

Box(app, height=10)

Text(app, text="Texto Convertido:")
texto_salida = TextBox(app, width=50, height=5, multiline=True, scrollbar=True)

Box(app, height=10)
actualizar_interfaz()
app.display()

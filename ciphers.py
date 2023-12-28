import codecs
import base64
from Crypto.Cipher import DES, DES3, AES, ARC2
from Crypto.Util.Padding import pad, unpad
import hashlib
import urllib.parse
import json
import xml.sax.saxutils


def cifrado_generico(texto, clave, tipo, modo, es_descifrado):
    cipher = tipo.new(clave.encode("utf-8"), modo)
    func = cipher.decrypt if es_descifrado else cipher.encrypt
    if not es_descifrado:
        return func(pad(texto.encode("utf-8"), tipo.block_size)).hex()
    else:
        return unpad(func(bytes.fromhex(texto)), tipo.block_size).decode("utf-8")


def hash_generico(texto, tipo):
    hash_func = getattr(hashlib, tipo)
    return hash_func(texto.encode()).hexdigest()


def codificador_simple(tipo, es_descifrado):
    def codificador(texto):
        return (
            codecs.decode(texto, tipo) if es_descifrado else codecs.encode(texto, tipo)
        )

    return codificador


def rot47(texto):
    resultado = []
    for char in texto:
        ascii_val = ord(char)
        if 33 <= ascii_val <= 126:
            resultado.append(chr(33 + ((ascii_val + 14) % 94)))
        else:
            resultado.append(char)
    return "".join(resultado)


def encode_base64_utf16le(text):
    utf16le_encoded = text.encode("utf-16le")
    base64_encoded = base64.b64encode(utf16le_encoded)
    return base64_encoded.decode("ascii")


def decode_base64_utf16le(encoded_text):
    base64_decoded = base64.b64decode(encoded_text)
    text = base64_decoded.decode("utf-16le")
    return text


def json_escape(texto):
    texto_json = json.dumps(texto)
    if texto_json.endswith('\\n"'):
        texto_json = texto_json[:-3] + '"'
    return texto_json


def json_unescape(texto):
    return json.loads(texto)


def xml_escape(texto):
    return xml.sax.saxutils.escape(texto)


def xml_unescape(texto):
    return xml.sax.saxutils.unescape(texto)


def url_encode(texto):
    return urllib.parse.quote(texto)


def url_decode(texto):
    return urllib.parse.unquote(texto)


def xor_cifrado(texto, clave):
    return "".join(
        chr(ord(c) ^ ord(clave[i % len(clave)])) for i, c in enumerate(texto)
    )


def rc4_cifrado(texto, clave):
    S = list(range(256))
    j = 0
    out = []

    for i in range(256):
        j = (j + S[i] + ord(clave[i % len(clave)])) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    for char in texto:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(chr(ord(char) ^ S[(S[i] + S[j]) % 256]))

    return "".join(out)


def convertir_texto(texto_original, opcion, clave="", es_descifrado=False):
    opciones = {
        "ROT13": codificador_simple("rot_13", es_descifrado),
        "ROT47": lambda t: rot47(t) if not es_descifrado else rot47(t),
        "Base64": lambda t: base64.b64encode(t.encode()).decode()
        if not es_descifrado
        else base64.b64decode(t).decode(),
        "Base64 UTF-16LE": lambda t: encode_base64_utf16le(t)
        if not es_descifrado
        else decode_base64_utf16le(t),
        "Hexadecimal": lambda t: t.encode().hex()
        if not es_descifrado
        else bytes.fromhex(t).decode(),
        "JSON": lambda t: json_escape(t) if not es_descifrado else json_unescape(t),
        "XML": lambda t: xml_escape(t) if not es_descifrado else xml_unescape(t),
        "URL": lambda t: url_encode(t) if not es_descifrado else url_decode(t),
        "XOR": lambda t: xor_cifrado(t, clave),
        "RC4": lambda t: rc4_cifrado(t, clave),
        "RC2": lambda t: cifrado_generico(t, clave, ARC2, ARC2.MODE_ECB, es_descifrado),
        "DES": lambda t: cifrado_generico(t, clave, DES, DES.MODE_ECB, es_descifrado),
        "3DES": lambda t: cifrado_generico(
            t, clave, DES3, DES3.MODE_ECB, es_descifrado
        ),
        "AES": lambda t: cifrado_generico(t, clave, AES, AES.MODE_ECB, es_descifrado),
        "MD5": lambda t: hash_generico(t, "md5"),
        "SHA1": lambda t: hash_generico(t, "sha1"),
        "SHA224": lambda t: hash_generico(t, "sha224"),
        "SHA256": lambda t: hash_generico(t, "sha256"),
        "SHA384": lambda t: hash_generico(t, "sha384"),
        "SHA512": lambda t: hash_generico(t, "sha512"),
    }

    if opcion not in opciones:
        raise ValueError("Opción no soportada.")

    return opciones[opcion](texto_original)

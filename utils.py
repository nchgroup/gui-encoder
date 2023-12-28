encoders = ["ROT13", "ROT47", "Base64", "Base64 UTF-16LE", "Hexadecimal", "URL"]
escapes = ["JSON", "XML"]
cifrados_con_clave = ["XOR", "RC4", "RC2", "DES", "3DES", "AES"]
cifrados_hash = ["MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"]

coders = (
    ["Seleccionar"]
    + ["--- Encoders ---"]
    + encoders
    + ["--- Escapes ---"]
    + escapes
    + ["--- Cifrados con clave ---"]
    + cifrados_con_clave
    + ["--- Cifrados hash ---"]
    + cifrados_hash
)

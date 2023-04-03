import argparse
import json
import os
from pprint import pprint as pp
from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding

settings = {
    'initial_file': 'path/to/inital/file.txt',
    'encrypted_file': 'path/to/encrypted/file.txt',
    'decrypted_file': 'path/to/decrypted/file.txt',
    'symmetric_key': 'path/to/symmetric/key.txt',
    'public_key': 'path/to/public/key.pem',
    'secret_key': 'path/to/secret/key.pem',
}

with open('settings.json', 'w') as fp:
    json.dump(settings, fp)
with open('settings.json') as json_file:
    json_data = json.load(json_file)
# pp(json_data)

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-gen', '--generation', type=int,
                   help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption', type=str,
                   help='Запускает режим шифрования')
group.add_argument('-dec', '--decryption', type=str,
                   help='Запускает режим дешифрования')
args = parser.parse_args()

if args.generation is not None:
    with open("my_key.txt", "wb") as file:
        key = os.urandom(args.generation)
        file.write(key)
elif args.encryption is not None:
    file_name = "my_kye.txt"
    with open("my_kye.txt", "rb") as file:
        key = file.readlines()[0][:-1]

    padder = padding.ANSIX923(32).padder()
    text = bytes(args.encryption, 'UTF-8')
    padded_text = padder.update(text)+padder.finalize()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.SEED(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update()
else:
    print("penis3")

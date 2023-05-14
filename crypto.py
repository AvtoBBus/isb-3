import argparse
import binascii
import json
import os
from pprint import pprint as pp
from cryptography.hazmat.primitives import serialization, hashes, padding as prim_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import create_initial_file as cif


class MyClass():
    iv = bytes(0)
    setting_path = ""

    def __init__(self):
        self.setting_path = "settings.json"
        settings = {
            'initial_file': 'top_secret/initial_file.txt',
            'encrypted_file': 'top_secret/encrypted_file.txt',
            'decrypted_file': 'top_secret/decrypted_file.txt',
            'symmetric_key': 'top_secret/symmetric_key.txt',
            'public_key': 'top_secret/ultra_secret/public_key.pem',
            'secret_key': 'top_secret/ultra_secret/secret_key.pem',
        }
        with open(self.setting_path, 'w') as fp:
            json.dump(settings, fp)

    def generation(self) -> None:
        with open('settings.json') as json_file:
            json_data = json.load(json_file)
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        cif.create_file(json_data['initial_file'])
        private_key = keys
        public_key = keys.public_key()
        with open(json_data['public_key'], 'wb') as public_out:
            public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                     format=serialization.PublicFormat.SubjectPublicKeyInfo))
        with open(json_data['secret_key'], 'wb') as private_out:
            private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                        encryption_algorithm=serialization.NoEncryption()))
        c_symmetric_key = public_key.encrypt(os.urandom(16), asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        with open(json_data['symmetric_key'], 'wb') as simmetric_out:
            simmetric_out.write(c_symmetric_key)

    def encryption(self) -> None:
        with open('settings.json') as json_file:
            json_data = json.load(json_file)
        with open(json_data['secret_key'], 'rb') as pem_in:
            private_key = pem_in.read()
        d_private_key = load_pem_private_key(private_key, password=None,)
        with open(json_data['symmetric_key'], 'rb') as pem_in:
            enc_symmetric_key = pem_in.read()
        symmetric_key = d_private_key.decrypt(enc_symmetric_key, asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        padder = prim_padding.ANSIX923(algorithms.SEED.block_size).padder()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(symmetric_key),
                        modes.CBC(iv))
        encryptor = cipher.encryptor()
        with open(json_data['initial_file'], 'rb') as i_f, open(json_data['encrypted_file'], 'wb') as e_f:
            e_f.write(iv)
            padded_block = bytes("", encoding="UTF-8")
            while block := i_f.read(128):
                padded_block += padder.update(block)
            e_f.write(encryptor.update(padded_block) +
                      encryptor.update(padder.finalize()) +
                      encryptor.finalize())

    def decryption(self) -> None:
        with open('settings.json') as json_file:
            json_data = json.load(json_file)
        with open(json_data['secret_key'], 'rb') as pem_in:
            private_key = pem_in.read()
        d_private_key = load_pem_private_key(private_key, password=None,)
        with open(json_data['symmetric_key'], 'rb') as pem_in:
            enc_symmetric_key = pem_in.read()
        symmetric_key = d_private_key.decrypt(enc_symmetric_key, asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        with open(json_data['encrypted_file'], 'rb') as f_in, open(json_data['decrypted_file'], 'wb') as f_out:
            iv = f_in.read(16)
            cipher = Cipher(algorithms.SEED(symmetric_key),
                            modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = prim_padding.ANSIX923(
                algorithms.SEED.block_size).unpadder()
            unpadded_block = bytes("", encoding="UTF-8")
            while block := f_in.read(128):
                unpadded_block += decryptor.update(block)
            f_out.write(unpadder.update(unpadded_block) +
                        unpadder.update(decryptor.finalize()) +
                        unpadder.finalize())


mc = MyClass()

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)

group.add_argument('-gen', '--generation',
                   help='Запускает режим генерации ключей')
group.add_argument('-enc', '--encryption',
                   help='Запускает режим шифрования, результат шифрования помещается в файл c_text.txt')
group.add_argument('-dec', '--decryption',
                   help='Запускает режим дешифрования, на вход подаётся путь то .txt файла с зашифрованным текстом')
args = parser.parse_args()


if args.generation is not None:
    mc.generation()
if args.encryption is not None:
    mc.encryption()
if args.decryption is not None:
    mc.decryption()

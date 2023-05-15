import argparse
import json
import os
import logging
from cryptography.hazmat.primitives import serialization, hashes, padding as prim_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import create_initial_file as cif
import config as cf


class Generator():
    setting_path = ""

    def __init__(self, setting_path: str):
        '''
        args:
            setting_path : str - путь до файла с "настройками"
        '''
        self.setting_path = setting_path
        with open(setting_path, 'w') as fp:
            json.dump(cf.SETTINGS, fp)

    def generation(self) -> None:
        '''
        Метод генерации симметричного и асимметричного ключа с последующим сохранением их в файлы
        '''
        try:
            with open(self.setting_path) as json_file:
                json_data = json.load(json_file)
        except FileNotFoundError:
            logging.error(f"{self.setting_path} not found")
        keys = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        logging.info("===Start generate keys===\n")
        cif.create_file(json_data['initial_file'])
        logging.info("Initial file create\n")
        private_key = keys
        public_key = keys.public_key()
        try:
            with open(json_data['public_key'], 'wb') as public_out:
                public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo))
            logging.info("Public key create\n")
        except FileNotFoundError:
            logging.error(f"{json_data['public_key']} not found")
        try:
            with open(json_data['secret_key'], 'wb') as private_out:
                private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm=serialization.NoEncryption()))
            logging.info("Secret key create\n")
        except FileNotFoundError:
            logging.error(f"{json_data['secret_key']} not found")
        c_symmetric_key = public_key.encrypt(os.urandom(16), asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        try:
            with open(json_data['symmetric_key'], 'wb') as simmetric_out:
                simmetric_out.write(c_symmetric_key)
            logging.info("Symmetric key create\n")
        except FileNotFoundError:
            logging.error(f"{json_data['symmetric_key']} not found")
        logging.info("===Finish generate keys===\n")


class Encryptor():
    setting_path = ""

    def __init__(self, setting_path: str):
        '''
        args:
            setting_path : str - путь до файла с "настройками"
        '''
        self.setting_path = setting_path
        with open(setting_path, 'w') as fp:
            json.dump(cf.SETTINGS, fp)

    def encryption(self) -> None:
        '''
        Метод шифрует данные в initial_file.txt, используя симметричный и асимметричный ключи, затем сохраняет результат в encrypted_file.txt
        '''
        logging.info("===Start encrypted===\n")
        try:
            with open(self.setting_path) as json_file:
                json_data = json.load(json_file)
        except FileNotFoundError:
            logging.error(f"{self.setting_path} not found")
        try:
            with open(json_data['secret_key'], 'rb') as pem_in:
                private_key = pem_in.read()
        except FileNotFoundError:
            logging.error(f"{json_data['secret_key']} not found")
        d_private_key = load_pem_private_key(private_key, password=None,)
        try:
            with open(json_data['symmetric_key'], 'rb') as pem_in:
                enc_symmetric_key = pem_in.read()
        except FileNotFoundError:
            logging.error(f"{json_data['symmetric_key']} not found")
        symmetric_key = d_private_key.decrypt(enc_symmetric_key, asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        padder = prim_padding.ANSIX923(algorithms.SEED.block_size).padder()
        iv = os.urandom(16)
        cipher = Cipher(algorithms.SEED(symmetric_key),
                        modes.CBC(iv))
        encryptor = cipher.encryptor()
        try:
            with open(json_data['initial_file'], 'rb') as i_f, open(json_data['encrypted_file'], 'wb') as e_f:
                e_f.write(iv)
                padded_block = bytes("", encoding="UTF-8")
                while block := i_f.read(128):
                    padded_block += padder.update(block)
                e_f.write(encryptor.update(padded_block) +
                          encryptor.update(padder.finalize()) +
                          encryptor.finalize())
        except FileNotFoundError:
            logging.error(f"{json_data['initial_file']} not found" if not os.path.isfile(
                json_data['initial_file']) else f"{json_data['encrypted_file']} not found")
        logging.info(
            f"===Finish encrypted===\nResult in file {json_data['encrypted_file']}")


class Decryptor():
    setting_path = ""

    def __init__(self, setting_path: str):
        '''
        args:
            setting_path - путь до файла с "настройками"
        '''
        self.setting_path = setting_path
        with open(setting_path, 'w') as fp:
            json.dump(cf.SETTINGS, fp)

    def decryption(self) -> None:
        '''
        Метод дешифрует данные в encrypted_file.txt, используя симметричный и асимметричный ключи, затем сохраняет результат в decrypted_file.txt
        '''
        logging.info("===Start decrypted===\n")
        try:
            with open(self.setting_path) as json_file:
                json_data = json.load(json_file)
        except FileNotFoundError:
            logging.error(f"{self.setting_path} not found")
        try:
            with open(json_data['secret_key'], 'rb') as pem_in:
                private_key = pem_in.read()
        except FileNotFoundError:
            logging.error(f"{json_data['secret_key']} not found")
        d_private_key = load_pem_private_key(private_key, password=None,)
        try:
            with open(json_data['symmetric_key'], 'rb') as pem_in:
                enc_symmetric_key = pem_in.read()
        except FileNotFoundError:
            logging.error(f"{json_data['symmetric_key']} not found")
        symmetric_key = d_private_key.decrypt(enc_symmetric_key, asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
        try:
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
        except FileNotFoundError:
            logging.error(f"{json_data['encrypted_file']} not found" if not os.path.isfile(
                json_data['encrypted_file']) else f"{json_data['decrypted_file']} not found")
        logging.info(
            f"===Finish encrypted===\nResult in file {json_data['decrypted_file']}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-gen', '--generation',
                       help='Запускает режим генерации ключей')
    group.add_argument('-enc', '--encryption',
                       help='Запускает режим шифрования, результат шифрования помещается в файл c_text.txt')
    group.add_argument('-dec', '--decryption',
                       help='Запускает режим дешифрования, на вход подаётся путь то .txt файла с зашифрованным текстом')
    args = parser.parse_args()
    setting_path = "settings.json"
    if args.generation:
        generator = Generator(setting_path)
        generator.generation()
    if args.encryption:
        encryptor = Encryptor(setting_path)
        encryptor.encryption()
    if args.decryption:
        decryptor = Decryptor(setting_path)
        decryptor.decryption()

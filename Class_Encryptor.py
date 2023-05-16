import argparse
import json
import os
import logging
from cryptography.hazmat.primitives import hashes, padding as prim_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import config as cf


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

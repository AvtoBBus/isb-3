import json
import os
import logging
import create_initial_file as cif
import config as cf
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding


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

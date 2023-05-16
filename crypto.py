import argparse
from generator import Generator
from encryptor import Encryptor
from decryptor import Decryptor

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

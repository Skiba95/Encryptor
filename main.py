from cryptography.fernet import Fernet, InvalidToken
import base64
import getpass
import pandas as pd

def generate_key(password: str) -> bytes:

    return base64.urlsafe_b64encode(password.ljust(32).encode()[:32])

def encrypt_data(data: str, password: str) -> str:

    key = generate_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str, password: str) -> str:

    key = generate_key(password)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_data.encode()).decode()

def process_csv(file_path: str, password: str, mode: str):

    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()
    
    required_columns = ['PrivateKey', 'Mnemonic']
    if not all(col in df.columns for col in required_columns):
        print(f"Ошибка: В файле отсутствуют необходимые колонки: {required_columns}")
        return

    try:
        if mode == 'encrypt':
            df['PrivateKey'] = df['PrivateKey'].apply(lambda x: encrypt_data(str(x), password))
            df['Mnemonic'] = df['Mnemonic'].apply(lambda x: encrypt_data(str(x), password))
        
        elif mode == 'decrypt':

            temp_df = df.copy()
            temp_df['PrivateKey'] = temp_df['PrivateKey'].apply(lambda x: decrypt_data(str(x), password))
            temp_df['Mnemonic'] = temp_df['Mnemonic'].apply(lambda x: decrypt_data(str(x), password))

            df = temp_df

        df.to_csv(file_path, index=False)
        print(f"Данные успешно обработаны и сохранены в {file_path}")

    except InvalidToken:
        print("Ошибка: Неверный пароль! Дешифрование не выполнено.")

    except Exception as e:
        print(f"Ошибка обработки файла: {str(e)}")

def main():
    file_path = input("Введите путь к CSV-файлу: ")
    password = getpass.getpass("Введите пароль для шифрования/дешифрования: ")
    choice = input("Выберите действие: (1) Шифрование, (2) Дешифрование: ")

    if choice == '1':
        process_csv(file_path, password, 'encrypt')
    elif choice == '2':
        process_csv(file_path, password, 'decrypt')
    else:
        print("Неверный выбор!")

if __name__ == "__main__":
    main()

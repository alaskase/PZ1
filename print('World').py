import hashlib

def hash_password(password):
    
    password_bytes = password.encode('utf-8')    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(password_bytes)
    hashed_bytes = sha256_hash.digest()
    hashed_string = hashed_bytes.hex()

    return hashed_string

password = input("Введите пароль: ")
hashed_password = hash_password(password)

print("Хешированный пароль: ", hashed_password)
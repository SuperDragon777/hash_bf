import hashlib

def hash_input(text):
    
    text_bytes = text.encode('utf-8')
    
    hashes = {
        'MD5': hashlib.md5(text_bytes).hexdigest(),
        'SHA-1': hashlib.sha1(text_bytes).hexdigest(),
        'SHA-256': hashlib.sha256(text_bytes).hexdigest(),
        'SHA-512': hashlib.sha512(text_bytes).hexdigest(),
        'SHA3-256': hashlib.sha3_256(text_bytes).hexdigest(),
        'SHA3-512': hashlib.sha3_512(text_bytes).hexdigest(),
        'BLAKE2b': hashlib.blake2b(text_bytes).hexdigest(),
    }
    
    return hashes

if __name__ == '__main__':
    print('SIMPLE HASHER\n')
    user_input = input('Введите текст для хеширования: ')
    
    print(f'\nХеши для: "{user_input}"\n')
    
    result = hash_input(user_input)
    
    for algorithm, hash_value in result.items():
        print(f'{algorithm:12} : {hash_value}')
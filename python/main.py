import hashlib
import itertools
import string

def brute_force(target_hash, max_len=6):
    charset = string.ascii_lowercase + string.digits
    total = sum(len(charset)**i for i in range(1, max_len + 1))
    attempt = 0
    
    algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }
    
    for length in range(1, max_len + 1):
        print(f"\n[*] Проверяю пароли длины {length}...")
        for combo in itertools.product(charset, repeat=length):
            pwd = ''.join(combo)
            attempt += 1
            
            if attempt % 10000 == 0:
                percent = (attempt / total) * 100
                print(f"    [{attempt:,}] {percent:.1f}%", end='\r')
            
            for algo_name, algo_func in algorithms.items():
                hsh = algo_func(pwd.encode()).hexdigest()
                if hsh == target_hash:
                    print(f"\n[✓] НАЙДЕНО!")
                    print(f"    Пароль: {pwd}")
                    print(f"    Алгоритм: {algo_name.upper()}")
                    print(f"    Попыток: {attempt:,}")
                    return pwd
    
    print(f"\n[✗] Не найдено (проверено: {attempt:,})")
    return None

if __name__ == "__main__":
    print("HASH BRUTE FORCER")
    
    user_hash = input("\nВведите хеш для перебора: ").strip()
    
    if not user_hash:
        print("[!] Хеш не введен")
    else:
        print(f"\n[*] Проверяю все алгоритмы...")
        brute_force(user_hash, 6)
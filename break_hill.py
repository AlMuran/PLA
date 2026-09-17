import numpy as np
from random import randint, seed

ALPHABET = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ .,?"
N = len(ALPHABET)  # 37

def char_to_num(c):
    return ALPHABET.index(c)

def num_to_char(x):
    return ALPHABET[x % N]

def text_to_nums(text):
    return [char_to_num(c) for c in text]

def nums_to_text(nums):
    return "".join(num_to_char(x) for x in nums)

# ищем обратный элемент по модулю m
def mod_inv(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"Нет обратного для {a} по модулю {m}")

# вычисляем определитель матрицы 2х2 п модулю N
def mat_det_2x2(M):
    return (M[0][0]*M[1][1] - M[0][1]*M[1][0]) % N

# вычисляем обратную матрицу 2х2 по модулю N
def mat_inv_2x2(M):
    det = mat_det_2x2(M)
    det_inv = mod_inv(det, N)
    return [
        [( M[1][1] * det_inv) % N, (-M[0][1] * det_inv) % N],
        [(-M[1][0] * det_inv) % N, ( M[0][0] * det_inv) % N],
    ]

# вычисляем произведение матриц 2х2 по модулю N
def mat_mul_2x2(A, B):
    return [
        [(A[0][0]*B[0][0] + A[0][1]*B[1][0]) % N,
         (A[0][0]*B[0][1] + A[0][1]*B[1][1]) % N],
        [(A[1][0]*B[0][0] + A[1][1]*B[1][0]) % N,
         (A[1][0]*B[0][1] + A[1][1]*B[1][1]) % N],
    ]


# вычисляем произведение матрицы 2х2 на вектор по модулю N
def mat_vec_2x2(M, v):
    return [
        (M[0][0]*v[0] + M[0][1]*v[1]) % N,
        (M[1][0]*v[0] + M[1][1]*v[1]) % N,
    ]

# генерируем случайный ключ 2x2
def gen_random_key_2x2():
    while True:
        K = [[randint(0, N-1), randint(0, N-1)],
             [randint(0, N-1), randint(0, N-1)]]
        det = mat_det_2x2(K)
        if det != 0 and np.gcd(det, N) == 1:
            return K

# шифруем текст с помощью шифра Хилла 2x2
def encrypt_hill_2x2(text, K):
    nums = text_to_nums(text)
    assert len(nums) % 2 == 0
    result = []
    for i in range(0, len(nums), 2):
        block = nums[i:i+2]
        enc = mat_vec_2x2(K, block)
        result.extend(enc)
    return nums_to_text(result)

# расшифровываем текст с помощью шифра Хилла 2x2
def decrypt_hill_2x2(cipher, K_inv):
    nums = text_to_nums(cipher)
    assert len(nums) % 2 == 0
    result = []
    for i in range(0, len(nums), 2):
        block = nums[i:i+2]
        dec = mat_vec_2x2(K_inv, block)
        result.extend(dec)
    return nums_to_text(result)

# восстанавливаем ключ по известному открытому и зашифрованному тексту
def recover_key(P1, C1):
    p_nums = text_to_nums(P1)
    c_nums = text_to_nums(C1)
    num_blocks = len(p_nums) // 2
    for i in range(num_blocks):
        for j in range(i+1, num_blocks):
            X = [[p_nums[2*i], p_nums[2*j]],
                 [p_nums[2*i+1], p_nums[2*j+1]]]
            Y = [[c_nums[2*i], c_nums[2*j]],
                 [c_nums[2*i+1], c_nums[2*j+1]]]
            detX = mat_det_2x2(X)
            if detX == 0 or np.gcd(detX, N) != 1:
                continue
            X_inv = mat_inv_2x2(X)
            K = mat_mul_2x2(Y, X_inv)
            return K
    raise ValueError("Не удалось восстановить ключ")
# 
def print_matrix(M, name="Матрица"):
    print(f"{name}:")
    for row in M:
        print("  [" + "  ".join(f"{x:2d}" for x in row) + " ]")

#seed(42)

P1 = "ПРАКЛИНАЛТОП"
P2 = "МУРАКАМИ ТОП"

K_secret = gen_random_key_2x2()
print_matrix(K_secret, "Секретный ключ")

C1 = encrypt_hill_2x2(P1, K_secret)
C2 = encrypt_hill_2x2(P2, K_secret)
print("\nШифртекст 1:", C1)
print("Шифртекст 2:", C2)

K_recovered = recover_key(P1, C1)
print_matrix(K_recovered, "Восстановленный ключ")

K_inv = mat_inv_2x2(K_recovered)
print_matrix(K_inv, "Обратный ключ")

P2_recovered = decrypt_hill_2x2(C2, K_inv)
print("Расшифрованное сообщение 2:", P2_recovered)

P1_check = decrypt_hill_2x2(C1, K_inv)
print("Проверка сообщения 1:", P1_check)

assert P2_recovered == P2, "Ошибка расшифровки!"
assert P1_check == P1, "Ошибка проверки!"
print("Всё сошлось")
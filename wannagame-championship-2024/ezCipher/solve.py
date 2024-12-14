from sage.all import *
from pwn import *
from os import urandom
from tqdm import tqdm


# io = process(["python3", "server.py"])
# io = remote("127.0.0.1", 12001)
io = remote("154.26.136.227", 63064)
x  = var('x')
F  = GF(2**16, name='x', modulus=x**16 + x**14 + x**12 + x**11 + x**9 + x**6 + x**4 + x**2 + 1)
P  = PolynomialRing(F, names='m0,m1,m2,m3,c0,c1,c2,c3'); (m0, m1, m2, m3, c0, c1, c2, c3) = P.gens()


def get_token(encrypt: callable):
    io.sendlineafter(b"> ", b"2")
    io.recvuntil(b"ping: ")
    ping = bytes.fromhex(io.recvline().strip().decode())
    io.sendlineafter(b"pong: ", encrypt(ping).hex().encode())
    io.recvuntil(b"token: ")
    return bytes.fromhex(io.recvline().strip().decode())

def collect_args(num_samples=1309):
    pairs       = []
    chunk       = 1309
    for i in tqdm(range(num_samples//chunk), desc="Collecting samples"):
        pt = urandom(8*chunk)
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b"pt: ", pt.hex().encode())
        io.recvuntil(b"ct: ")
        ct = bytes.fromhex(io.recvline().strip().decode())
        for j in range(0, 8*chunk, 8):
            pairs.append((pt[j:j+8], ct[j:j+8]))

    args = []
    for x, y in pairs:
        arr = []
        for i in range(0, 8, 2):
            arr.append(F.from_integer(int.from_bytes(x[i:i+2], 'little')))
        for i in range(0, 8, 2):
            arr.append(F.from_integer(int.from_bytes(y[i:i+2], 'little')))
        args.append(arr)
    return args

def solve_stage1():
    print("Stage 1: Recovering the encryption polynomial")
    fn = [m0, m1, m2, m3]
    for _ in range(3):
        for index in range(4):
            fn[index] += (fn[(index + 1) % 4] + F.random_element()) ** 3 + F.from_integer(3)
    fn_monomials = [f.monomials()[:-1] for f in fn] # remove the constant term

    gn = [c0, c1, c2, c3]
    for index in reversed(range(4)):
        gn[index] += (gn[(index + 1) % 4] + F.random_element()) ** 3 + F.from_integer(3)
    gn_monomials = [g.monomials()[:-1] for g in gn] # remove the constant term

    fn_recovered = []
    gn_recovered = []
    args         = collect_args()

    for index in range(4):
        fg_monomials = fn_monomials[index] + gn_monomials[index]
        mat, vec     = [], []

        for arg in tqdm(args, desc=f"Recovering f[{index}] and g[{index}]"):
            # Standardize the coefficients of highest degree monomials to 1
            vec.append(fg_monomials[0](*arg))

            def eval_monomial(monomial):
                return monomial(*arg)

            row = [eval_monomial(monomial) for monomial in fg_monomials[1:]]
            row.append(1) # constant coefficient
            mat.append(row)

        mat = Matrix(mat)
        vec = vector(vec)
        res = mat.solve_right(vec)

        fi_deg = len(fn_monomials[index])
        fi     = fn_monomials[index][0] # Don't forget the highest-degree monomial
        fi    += sum(coeff * monomial for coeff, monomial in zip(res[:fi_deg-1], fn_monomials[index][1:]))
        fi    += res[-1]                # Constant coeff: note that it also contains the Constant coeff of gi
        fn_recovered.append(fi)

        gi = sum(coeff * monomial for coeff, monomial in zip(res[fi_deg-1:-1], gn_monomials[index]))
        gn_recovered.append(gi)

    r_keys = []
    c_vars = [c0, c1, c2, c3]
    remove = 0
    for i in reversed(range(4)):
        k = gn_recovered[i].monomial_coefficient(c_vars[(i + 1) % 4]**2) + remove
        r_keys.append(k)
        remove = (remove + k) ** 3 + F.from_integer(3)
    r_keys = r_keys[::-1]

    gn_without_const = [c0, c1, c2, c3]
    for i in reversed(range(4)):
        gn_without_const[i] += (gn_without_const[(i + 1) % 4] + r_keys[i]) ** 3 + F.from_integer(3)
        gn_const             = (gn_recovered[i] + gn_without_const[i])
        fn_recovered[i]     += gn_const

    def encrypt(plaintext: bytes) -> bytes:
        ciphertext = b""
        for i in range(0, len(plaintext), 8):
            block = plaintext[i : i + 8]
            block = [F.from_integer(int.from_bytes(block[i : i + 2], "little")) for i in range(0, 8, 2)]
            block += [0] * 4

            block = [fn_recovered[i](*block) for i in range(4)]
            for i in range(4):
                block[i] += (block[(i + 1) % 4] + r_keys[i]) ** 3 + F.from_integer(3)
            
            block = [int(v.to_integer()).to_bytes(2, "little") for v in block]
            ciphertext += b''.join(block)
        return ciphertext

    return encrypt

def solve_stage2(recovered_encrypt):
    print("Stage 2: Recovering the flag")
    xor_flags = []

    for _ in tqdm(range(255), desc="Collecting XOR-flags"):
        decrypted_xor_flag = get_token(recovered_encrypt)
        xor_flags.append(recovered_encrypt(decrypted_xor_flag))

    mat = []
    for c in xor_flags:
        row = list(map(lambda f: (-1)**int(f), bin(int(c.hex(), 16))[2:].zfill(256)))
        mat.append(row)

    mat = Matrix(mat)
    sol = mat.right_kernel().basis()[0]

    s1 = int("".join(map(lambda f: str(int(f ==  1)), sol)), 2).to_bytes(32, 'big').hex()
    s2 = int("".join(map(lambda f: str(int(f == -1)), sol)), 2).to_bytes(32, 'big').hex()
    
    print(s1)
    print(s2)
    
    io.sendlineafter(b"> ", b"3")
    io.sendline(s2.encode())

if __name__ == "__main__":
    recovered_encryptor = solve_stage1()
    solve_stage2(recovered_encryptor)
    io.interactive()
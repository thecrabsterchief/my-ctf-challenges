from sage.all import PolynomialRing, matrix, block_matrix, randint, GF, inverse_mod, ZZ, zero_matrix, identity_matrix, vector, prod, gcd
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from public.utils import AEMC
import math
import struct

def kannan_cvp(mat, target, reduction=lambda M: M.BKZ(), weight=None):
    if weight is None:
        weight = max(target)
    L = block_matrix([[mat, 0], [-matrix(target), weight]])
    for row in reduction(L):
        if row[-1] < 0:
            row = -row
        if row[-1] == weight:
            return row[:-1] + target

MAX_ROUNDS = 20
N_PLAYERS  = 512
INFO       = b"W3llc0m3 t0 W4nn4G4m3 Ch4mpi0nsh1p 2023"
MASK_R     = 0x1337fffc0ffffffc0ffffffc0fff1337
MASK_S     = 0xffffffffffffffffffffffffffffffff
P          = 0x7ffffffffffffffffffffffffffffffbb
Q          = 0x100000000000000000000000000000000
RR         = GF(P)
PR         = PolynomialRing(RR, "x"); x = PR.gen()

def info_players():
    players = []
    io.sendlineafter(b"> ", b"1")
    for _ in range(N_PLAYERS):
        io.recvuntil(b"> ")
        players.append(io.recvline().strip().decode())

    return players

def generate_task():
    io.sendlineafter(b"> ", b"2")
    io.recvuntil(b"> ")
    return io.recvline().strip().decode()

def do_task(token: str):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> Enter Task Token (in base64): ", token.encode())
    return b"Doing task..." in io.recvline()

def report_impostor(who: str):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"> Who? ", who.encode())
    assert b"Good!" in io.recvline()

def generate_passwords(players, salt):
    res  = []

    for player in players:
        master_key = HKDF(
            algorithm=hashes.BLAKE2b(digest_size=64),
            salt=salt,
            info=INFO,
            length=32
        ).derive(player.encode())
        
        cipher  = AES.new(key=master_key, mode=AES.MODE_CTR, nonce=salt)
        mac_key = cipher.encrypt(bytes(32))
        r       = int.from_bytes(mac_key[0x00:0x10], byteorder='little') & MASK_R
        s       = int.from_bytes(mac_key[0x10:0x20], byteorder='little') ^ MASK_S
        res.append((master_key, r, s))
    
    return res

def generate_multicollisions(player_list, salt):
    # reference: https://www.kryptoslogic.com/blog/2021/01/faster-poly1305-key-multicollisions/
    # Step 0: Initialize
    MASTER_KEY, R, S = zip(*generate_passwords(player_list, salt))
    l = len(MASTER_KEY)
    d = 20
    N = l+d # number of 16-bytes-blocks in ciphertext
    tag = randint(0, Q)

    # === Step 1: Interpolation ===
    # The head blocks of mac_data
    F = AEMC.pad(INFO, 16)
    F = [F[i:i+16] for i in range(0, len(F), 16)]
    F = PR([int.from_bytes(f, 'little') + 2**128 for f in reversed(F)])

    # The tail block of mac_data
    E = int.from_bytes(struct.pack('<QQ', len(INFO), 16*N), 'little') + 2**128

    T = [ (((tag - S[i]) % Q) - E*R[i] - ZZ(F(R[i]))*R[i]**(N+2)) * pow(R[i]**2, -1, P) % P for i in range(l) ]
    m = PR.lagrange_polynomial(zip(R, T))

    # Step 2: Redundancy
    p = prod([ x - ri for ri in R ])
    f = 0
    while gcd(f, p) != 1:
        f = x**d + PR.random_element(d-1)

    ma = m * f * inverse_mod(f, p) % (p*f)
    mb =     p * inverse_mod(p, f) % (p*f)

    # Step 3: Lattice Reduction
    qL = matrix(RR, [ list(x**i * mb % (p*f)) for i in range(d) ])
    zL = block_matrix(ZZ, 2, 1, [
        qL.echelon_form().change_ring(ZZ),
        block_matrix(ZZ, 1, 2, [zero_matrix(l, d), identity_matrix(ZZ, l) * P])
    ])
    target = vector([ ZZ((2**128 + Q//2) - ma[i]) for i in range(N) ])

    # Build Kannan Embedding
    W = 2**114 # P^(l/(l+d)) / (2*delta^(l+d)) ???
    v = kannan_cvp(mat=zL.BKZ(), target=target, weight=W)

    final = vector(ZZ, (vector(v)+vector(ma))%P)
    ciphertext = b''.join([ int(block % 2**128).to_bytes(16, 'little') for block in reversed(final) ]) + tag.to_bytes(16, 'little')
    
    return base64.b64encode(ciphertext).decode(), player_list

if __name__ == "__main__":
    import os
    from tqdm import tqdm
    from multiprocessing import Pool
    from pwn import remote, process, success
    from itertools import repeat

    # io = process(["python3", "src/server.py"])
    io = remote("157.245.147.89", 12001)
    io.sendline(b"")

    for round in range(MAX_ROUNDS):
        success("Solving Round {:02d}...".format(round + 1))
        
        io.recvuntil(b"[*] This Game's Token: ")
        salt    = bytes.fromhex(io.recv(24).decode())
        players = info_players()

        # optimize
        intervals = [
            players[i:i+64] for i in range(0, len(players), 64)
        ]
        with Pool(os.cpu_count()) as executor:
            for ciphertext, player_list in tqdm(executor.starmap(generate_multicollisions, zip(intervals, repeat(salt)))):
                if do_task(ciphertext):
                    players = player_list

        while (l := len(players)) > 1:
            mid = math.ceil(l/2)
            ciphertext, _ = generate_multicollisions(players[:mid], salt)

            if do_task(ciphertext):
                players = players[:mid]
            else:
                players = players[mid:]

        impostor = players[0]
        report_impostor(who=impostor)

    print(io.recvline())
    io.close()
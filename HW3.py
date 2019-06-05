"""
Authors:
Alex Weizman, 314342064
Michael Afonin, 310514997
"""

from HW2 import des_encrypt,des_decrypt,binary_string,plaintobin,xor



def split_to_blocks(plaintext):
    text = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    if len(text[-1])<8:
        while len(text[-1])<8:
            text[-1]+=" "
    return text

def ecb_encrypt(plain,key):
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        result+=des_encrypt(block,key)
    return result

def ecb_decrypt(cipher,key):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        result+=des_decrypt(block,key)
    return result

def cbc_encrypt(plain,key,iv):
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        bin_block=plaintobin(block)
        bin_iv=plaintobin(iv)
        xored=binary_string(xor(bin_block,bin_iv,64))
        iv=des_encrypt(xored,key)
        result+=iv
    return result

def cbc_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        bin_iv=plaintobin(iv)
        code=des_decrypt(block,key)
        bin_code=plaintobin(code)
        xored=binary_string(xor(bin_code,bin_iv,64))
        iv=block
        result+=xored
    return result

def ofb_encrypt(code,key,iv):
    blocks=split_to_blocks(code)
    result=""
    for block in blocks:
        iv=des_encrypt(iv,key)
        bin_iv=plaintobin(iv)
        bin_block=plaintobin(block)
        xored=binary_string(xor(bin_block,bin_iv,64))
        result+=xored
    return result

def ofb_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        iv=des_encrypt(iv,key)
        bin_iv=plaintobin(iv)
        bin_block=plaintobin(block)
        xored=binary_string(xor(bin_block,bin_iv,64))
        result+=xored
    return result

def cfb_encrypt(plain,key,iv):
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        enc_iv=des_encrypt(iv,key)
        bin_iv=plaintobin(enc_iv)
        bin_block=plaintobin(block)
        xored=binary_string(xor(bin_block,bin_iv,64))
        iv=xored
        result+=xored
    return result

def cfb_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        enc_iv=des_encrypt(iv,key)
        bin_iv=plaintobin(enc_iv)
        bin_block=plaintobin(block)
        xored=binary_string(xor(bin_block,bin_iv,64))
        iv=block
        result+=xored
    return result

def ctr_encrypt(plain,key,nunce):
    ctr=0
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        bin_nunce=plaintobin(nunce)
        bin_ctr='{0:064b}'.format(ctr)
        new_nunce=binary_string(xor(bin_nunce,bin_ctr,64))
        enc_ctr=des_encrypt(new_nunce,key)
        bin_block=plaintobin(block)
        bin_enc=plaintobin(enc_ctr)
        xored=binary_string(xor(bin_enc,bin_block,64))
        ctr+=1
        result+=xored
    return result

def ctr_decrypt(cipher,key,nunce):
    ctr=0
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        bin_nunce=plaintobin(nunce)
        bin_ctr='{0:064b}'.format(ctr)
        new_nunce=binary_string(xor(bin_nunce,bin_ctr,64))
        enc_ctr=des_encrypt(new_nunce,key)
        bin_enc=plaintobin(enc_ctr)
        bin_block=plaintobin(block)
        xored=binary_string(xor(bin_enc,bin_block,64))
        ctr+=1
        result+=xored
    return result

code="sometext sometext sometext sometext"
key="nonsense"
iv="mySecret"
nunce="itsnunce"
print("ECB Mode:")
print("Encrypt:")
print(ecb_encrypt(code,key))
print("Decryt:")
print(ecb_decrypt(ecb_encrypt(code,key),key))
print("CBC Mode:")
print("Encrypt:")
print(cbc_encrypt(code,key,iv))
print("Decryt:")
print(cbc_decrypt(cbc_encrypt(code,key,iv),key,iv))
print("OFB Mode:")
print("Encrypt:")
print(ofb_encrypt(code,key,iv))
print("Decryt:")
print(ofb_decrypt(ofb_encrypt(code,key,iv),key,iv))
print("CFB Mode:")
print("Encrypt:")
print(cfb_encrypt(code,key,iv))
print("Decryt:")
print(cfb_decrypt(cfb_encrypt(code,key,iv),key,iv))
print("CTR Mode:")
print("Encrypt:")
print(ctr_encrypt(code,key,iv))
print("Decrypt:")
print(ctr_decrypt(ctr_encrypt(code,key,nunce),key,nunce))
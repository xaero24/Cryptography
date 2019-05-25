import HW2
from HW2 import des_encrypt,des_decrypt,plaintobin,xor,back_to_plain

def split_to_blocks(plaintext):
    text = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    if len(text[-1])<8:
        while len(text[-1])<8:
            text[-1]+=""
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
        xored=back_to_plain(xor(bin_block,bin_iv,64))
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
        xored=back_to_plain(xor(bin_code,bin_iv,64))
        iv=cipher
        result+=xored
    return result

def ofb_encrypt(code,key,iv):
    blocks=split_to_blocks(code)
    result=""
    for block in blocks:
        iv=des_encrypt(iv,key)
        bin_iv=plaintobin(iv)
        bin_block=plaintobin(block)
        xored=back_to_plain(xor(bin_block,bin_iv,64))
        result+=xored
    return result

def ofb_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        iv=des_encrypt(iv,key)
        bin_iv=plaintobin(iv)
        bin_block=plaintobin(block)
        xored=back_to_plain(xor(bin_block,bin_iv,64))
        result+=xored
    return result

def cfb_encrypt(plain,key,iv):
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        enc_iv=des_encrypt(iv,key)
        bin_iv=plaintobin(enc_iv)
        bin_block=plaintobin(block)
        xored=back_to_plain(xor(bin_block,bin_iv,64))
        iv=xored
        result+=xored
    return result

def cfb_decrypt(code,key,iv):
    blocks=split_to_blocks(code)
    result=""
    for block in blocks:
        enc_iv=des_encrypt(iv,key)
        bin_iv=plaintobin(enc_iv)
        bin_block=plaintobin(block)
        xored=back_to_plain(xor(bin_block,bin_iv,64))
        iv=block
        result+=xored
    return result

#def ctr_encrypt(plain,key):
#    ctr=0
#    blocks=split_to_blocks(plain)
#    result=""
#    for block in blocks:
#        bin_ctr='{0:064b}'.format(ctr)

#        plain_ctr=back_to_plain(bin_ctr)
#        enc_ctr=des_encrypt(plain_ctr,key)
#        bin_block=plaintobin(block)
#        xored=xor(enc_ctr,bin_block,64)
#        ctr+=1
#        result+=xored
#    return result
from crypto2 import des,des_dicrypte,Xor,cut,to_binary,reverse_from_bit



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
        result+=des(block,key)
    return result

def ecb_decrypt(cipher,key):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        result+=des_dicrypte(block,key)
    return result

def cbc_encrypt(plain,key,iv):
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        bin_block=to_binary(block)
        bin_iv=to_binary(iv)
        xored=reverse_from_bit(Xor(bin_block,bin_iv,64))
        iv=des(xored,key)
        result+=iv
    return result

def cbc_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        bin_iv=to_binary(iv)
        code=des_dicrypte(block,key)
        bin_code=to_binary(code)
        xored=reverse_from_bit(Xor(bin_code,bin_iv,64))
        iv=block
        result+=xored
    return result

def ofb_encrypt(code,key,iv):
    blocks=split_to_blocks(code)
    result=""
    for block in blocks:
        iv=des(iv,key)
        bin_iv=to_binary(iv)
        bin_block=to_binary(block)
        xored=reverse_from_bit(Xor(bin_block,bin_iv,64))
        result+=xored
    return result

def ofb_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        iv=des(iv,key)
        bin_iv=to_binary(iv)
        bin_block=to_binary(block)
        xored=reverse_from_bit(Xor(bin_block,bin_iv,64))
        result+=xored
    return result

def cfb_encrypt(plain,key,iv):
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        enc_iv=des(iv,key)
        bin_iv=to_binary(enc_iv)
        bin_block=to_binary(block)
        xored=reverse_from_bit(Xor(bin_block,bin_iv,64))
        iv=xored
        result+=xored
    return result

def cfb_decrypt(cipher,key,iv):
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        enc_iv=des(iv,key)
        bin_iv=to_binary(enc_iv)
        bin_block=to_binary(block)
        xored=reverse_from_bit(Xor(bin_block,bin_iv,64))
        iv=block
        result+=xored
    return result

def ctr_encrypt(plain,key,nunce):
    ctr=0
    blocks=split_to_blocks(plain)
    result=""
    for block in blocks:
        bin_nunce=to_binary(nunce)
        bin_ctr='{0:064b}'.format(ctr)
        new_nunce=reverse_from_bit(Xor(bin_nunce,bin_ctr,64))
        enc_ctr=des(new_nunce,key)
        bin_block=to_binary(block)
        bin_enc=to_binary(enc_ctr)
        xored=reverse_from_bit(Xor(bin_enc,bin_block,64))
        ctr+=1
        result+=xored
    return result

def ctr_decrypt(cipher,key,nunce):
    ctr=0
    blocks=split_to_blocks(cipher)
    result=""
    for block in blocks:
        bin_nunce=to_binary(nunce)
        bin_ctr='{0:064b}'.format(ctr)
        new_nunce=reverse_from_bit(Xor(bin_nunce,bin_ctr,64))
        enc_ctr=des(new_nunce,key)
        bin_enc=to_binary(enc_ctr)
        bin_block=to_binary(block)
        xored=reverse_from_bit(Xor(bin_enc,bin_block,64))
        ctr+=1
        result+=xored
    return result


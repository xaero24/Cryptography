## DES Exercise
def hextobin(code):
    return bin(int(code,16))[2:].zfill(8)
    

#print(hextobin("d8164228f290cbaf"))

def plaintobin(msg):
    return ''.join(format(ord(x), 'b').zfill(8) for x in msg)

#print(plaintobin("nonsense"))
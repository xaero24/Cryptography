
#PART 1: Encryption and decryption

def Encrypt(msg, key):
    """
    To encrypt a message, one inputs a sentence and a key (alphabetical).
    Each letter in the text is parsed using the formula:

    C(i) = [ M(i)+K(i mod |K|) ] mod 26

    Where:
    M is the message and M(i) is the i-th letter in M;
    K is the key and K(i mod |K|) is the i-th letter of K, repeatedly used (hence mod length of the key);
    C is the resulting ciphertext and C(i) is the already encrypted letter.
    """
    cipher=""
    for i in range(0, len(msg)):
        cipher += (msg.replace(msg[i], chr((ord(msg[i])-65 + ord( key[i%len(key)] )-65 )%26 + 65)))[i]
    return cipher

def Decrypt(cipher, key):
    """
    To decrypt a message, one inputs a cipher and a key (alphabetical).
    Each letter in the cipher is parsed using the formula:

    M(i) = [ C(i)-K(i mod |K|) ] mod 26

    Where:
    C is the ciphertext and C(i) is the i-th letter in C;
    K is the key and K(i mod |K|) is the i-th letter of K, repeatedly used (hence mod length of the key);
    M is the resulting message and M(i) is the already deciphered letter.
    """
    msg=""
    for i in range(0, len(cipher)):
        msg += (cipher.replace(cipher[i], chr((ord(cipher[i])-65 - ord( key[i%len(key)] )-65 )%26 + 65)))[i]
    return msg

#==================================================#

#PART 2: Letter recurrance calculation

def CountCipherChars(cipher):
    """
    This function counts the amount of letters in a given text.
    The output is a dictionare, where the key is the letter and the value is its count.

    e.g. for ABCE the output is:
    {"A": 1, "B": 1, "C": 1, "D": 0, "E": 1, "F": 0, ... , "Z": 0}
    """
    #New empty dictionary:
    letterCount= {}

    #Initializing the dict with A-Z with zero counts:
    for let in range(26):
        letterCount[chr(let+65)] = 0
    
    #For each found letter, its count is increased:
    for let in range(len(cipher)):
        letterCount[cipher[let]] += 1
    
    return letterCount

#==================================================#

#PART 3: Index Of Coincidence

def CoincIndex(cipher):
    """
    For a given text, the function calculates the Index of Coincidence of the text.
    The formula is given sa follows:

    IC = sum[La*(La-1)] / [N*(N-1)/26]

    Where:
        La is the a'th letter's count (found in the dictionary)
        N is the amount of letters in the cipher
        26 is the amont of letters in English
    """
    if len(cipher) < 2:
        return 0
    
    letSum = 0
    letDict = CountCipherChars(cipher)
    for let in ''.join(sorted(set(cipher), key=cipher.index)):
        reps = letDict[let]
        letSum += reps*(reps-1)
    
    N=len(cipher)
    IC = letSum/(N*(N-1)/26)
    return IC

def KeyLengthGuesser(cipher):
    """
    Using the known IC for the English language (approx. 1.73), we can guess the key length.
    For larger texts the alculation will be more precise.
    The guess is based on calculating the IC of a given ciphertext.
    For certain lenghts the IC will be very close to 1.73, which indicates the closest guess for the key length.
    """
    minThreshold = 999
    expectedLength = 0
    for guess in range(1, 16):
        currentIC=0
        for mod in range(guess):
            tempString=""
            for index in range(len(cipher)):
                if mod+index*guess < len(cipher):
                    tempString += cipher[mod+index*guess]
            res=CoincIndex(tempString)
            currentIC += res

        if abs(currentIC/guess - 1.73) < minThreshold:
            minThreshold = abs( currentIC/guess - 1.73)
            expectedLength = guess
    
    return expectedLength

#==================================================#

#PART 4: Key calculation

def KeyCalculator(cipher):
    """
    The key calculation is based on "stacking" the cipher in groups of 'key length' on top of each other.
    For each "column" (essentialy a substring of the ciphertext encoded by the same letter) we:
    1. Try to decode it with a single letter;
    2. Check the chi (X) value for the decoded text;
    3. Choose the max value for chi and the letter that gave the result.

    For each "column" (substring as noted above) we find the correct value and add it to the key.
    The result is likely to be the key for the ciphertext.
    """
    guess = KeyLengthGuesser(cipher)
    calculatedKey =""
    engDict = {'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702, 'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153, 'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507, 'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056, 'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974, 'Z': 0.074}

    for position in range(guess):
        tempString = ""
        for mod in range(position, len(cipher), guess):
            if mod < len(cipher):
                tempString += cipher[mod]
                
        maxCalcForX = 0
        bestFitLetter = ''
        
        for let in range(26):
            decryptedCol = Decrypt(tempString, chr(let+65))
            letterDistribution = CountCipherChars(decryptedCol)
            X = sum( (letterDistribution[i]*engDict[i]) for i in letterDistribution )
            if X > maxCalcForX:
                maxCalcForX = X
                bestFitLetter = chr(let+65)
            
        calculatedKey += bestFitLetter
        
    return calculatedKey




#==================================================#

#PART 5: Message decryption

def Cyph0rHaXX0r(cipher):
    """
    The function simply gets a string - a cipthertext - and uses mathematical methods for calculating its key.
    The returned key is then used to decrypt the given text.
    """
    return Decrypt(cipher, KeyCalculator(cipher))

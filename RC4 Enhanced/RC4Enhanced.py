class Text(object):
    def __init__(self, filename):
        self.filename = filename

    def __str__(self):
        return f'{self.filename}'

    def text_to_bytes(self):
        with open(self.filename, 'r') as f:
            s = f.read()
        return [ord(byte) for byte in s]

    def hex_to_bytes(self):
        byteList = []
        with open(self.filename, 'r') as f:
            hexStr = f.read()
            for i in range(0, len(hexStr), 2):
                byte = hexStr[i:i + 2]
                byteList.append(int(f'0X{byte}', 16))

        return byteList

    def bytes_to_text(self, ByteList):
        s = ''.join(chr(byte) for byte in ByteList)
        with open(self.filename, 'w') as f:
            # on Windows, default coding for Chinese is GBK
            # s = s.decode('utf-8').encode('gbk')
            f.write(s)

    def bytes_to_hex(self, ByteList):
        with open(self.filename, 'w') as f:
            for byte in ByteList:
                hexStr = f'0{hex(byte)[2:]}'
                f.write(hexStr[-2:].upper())

    def encrypt(self, Key1, Key2):

        PlainBytes = self.text_to_bytes()
        KeyBytes1 = Key1.text_to_bytes()
        KeyBytes2 = Key2.text_to_bytes()
        KeystreamBytes, CipherBytes = crypt(PlainBytes, KeyBytes1, KeyBytes2)
        Keystream = Text('keystream.txt')
        Cipher = Text('hex.txt')
        Keystream.bytes_to_hex(KeystreamBytes)
        Cipher.bytes_to_hex(CipherBytes)

    def decrypt(self, Key1, Key2):

        CipherBytes = self.hex_to_bytes()
        KeyBytes1 = Key1.text_to_bytes()
        KeyBytes2 = Key2.text_to_bytes()
        KeystreamBytes, PlainBytes = crypt(CipherBytes, KeyBytes1, KeyBytes2)
        Plain = Text('plain.txt')
        Keystream = Text('keystream.txt')
        Keystream.bytes_to_hex(KeystreamBytes)
        Plain.bytes_to_text(PlainBytes)


def crypt(PlainBytes, KeyBytes1, KeyBytes2):
    keystreamList = []
    cipherList = []

    keyLen1 = len(KeyBytes1)
    keylen2 = len(KeyBytes2)
    plainLen = len(PlainBytes)
    S1 = range(256)
    S2 = range(256)

    j1 = j2 = 0
    for i in range(256):
        j1 = (j1 + S1[i] + KeyBytes1[i % keyLen1]) % 256
        S1[i], S1[j1] = S1[j1], S1[i]
        j2 = (j2 + S2[i] + KeyBytes2[i % keylen2]) % 256
        S2[i], S2[j2] = S2[j2], S2[i]

    i = 0
    j1 = j2 = 0
    for m in range(plainLen):
        i = (i + 1) % 256
        j1 = (j1 + S1[i]) % 256
        S1[i], S1[j1] = S1[j1], S1[i]
        j2 = (j2 + S2[i]) % 256
        S2[i], S2[j2] = S2[j2], S2[i]
        k = S1[(S1[i] + S1[j1]) % 256]
        k = (k+S2[(S2[i] + S2[j2]) % 256]) % 256
        keystreamList.append(k)
        cipherList.append(k ^ PlainBytes[m])

    return keystreamList, cipherList


def main(Filename="hex.txt", Action="decrypt", KeyName1='key1.txt', KeyName2="key2.txt"):
    try:
        f = open(Filename, 'r')
        f.close()
        f = open(KeyName1, 'r')
        f.close()
        f = open(KeyName2, 'r')
        f.close()
    except IOError:
        print('File(s) do not exist.\nUsage: RC4.py filename encrypt/decrypt [keyfile]')
    else:
        if Action == 'encrypt':
            Plain = Text(Filename)
            Key1 = Text(KeyName1)
            Key2 = Text(KeyName2)
            Plain.encrypt(Key1,Key2)
        elif Action == 'decrypt':
            Cipher = Text(Filename)
            Key1 = Text(KeyName1)
            Key2 = Text(KeyName2)
            Cipher.decrypt(Key1,Key2)
        else:
            print('Usage: RC4.py filename encrypt/decrypt [keyfile]')


if __name__ == '__main__':
    try:
        #main()
        print(' \n\n\n\n\t\t\t\t Enhanced RC4 (ARCFOUR) Algorithm \n\n\n\t 1) Encrypt \n\n\n\t 2) Decrypt \n\n\n\t 3) Exit \n\n\n\t Enter Your Choice : ')
        n=int(input())
        if n == 1:
            filename=input('Enter the filename to encrypt : ')
            key1=input('Enter the key 1 : ')
            with open("key1.txt", 'w') as f:
                f.write(key1)
            key2=input('Enter the key 2 : ')
            with open("key2.txt", 'w') as f:
                f.write(key2)
            main(filename,"encrypt","key1.txt","key2.txt")
            print(' \n\t Encryption Complete')
            print(' Key 1 : ',key1)
            print(' Key 2 : ',key2)
            with open("keystream.txt", 'r') as f:
                Str = f.read()
                print('Keystream : ',Str)
            with open("hex.txt", 'r') as f:
                Str = f.read()
                print('Encrypted Text : ',Str)
        elif n == 2:
            filename=input('Enter the filename to decrypt : ')
            key1=input('Enter the key 1 : ')
            with open("key1.txt", 'w') as f:
                f.write(key1)
            key2=input('Enter the key 2 : ')
            with open("key2.txt", 'w') as f:
                f.write(key2)
            main(filename,"decrypt","key1.txt","key2.txt")
            print(' \n\t Decryption Complete')
            print(' Key 1 : ',key1)
            print(' Key 2 : ',key2)
            with open("keystream.txt", 'r') as f:
                Str = f.read()
                print('Keystream : ',Str)
            with open("plain.txt", 'r') as f:
                Str = f.read()
                print('Decrypted Text : ',Str)
        elif n == 3:
            print('\n\n\n\tProgram about to exit ... ')
    except TypeError:
        print('Usage: RC4.py filename encrypt/decrypt [keyfile]')

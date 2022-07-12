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

    def encrypt(self, Key):

        PlainBytes = self.text_to_bytes()
        KeyBytes = Key.text_to_bytes()
        KeystreamBytes, CipherBytes = crypt(PlainBytes, KeyBytes)
        Keystream = Text('keystream.txt')
        Cipher = Text('hex.txt')
        Keystream.bytes_to_hex(KeystreamBytes)
        Cipher.bytes_to_hex(CipherBytes)

    def decrypt(self, Key):

        CipherBytes = self.hex_to_bytes()
        KeyBytes = Key.text_to_bytes()
        KeystreamBytes, PlainBytes = crypt(CipherBytes, KeyBytes)
        Plain = Text('plain.txt')
        Keystream = Text('keystream.txt')
        Keystream.bytes_to_hex(KeystreamBytes)
        Plain.bytes_to_text(PlainBytes)


def crypt(PlainBytes, KeyBytes):
    keystreamList = []
    cipherList = []

    keyLen = len(KeyBytes)
    plainLen = len(PlainBytes)
    S = range(256)

    j = 0
    for i in range(256):
        j = (j + S[i] + KeyBytes[i % keyLen]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    for m in range(plainLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        keystreamList.append(k)
        cipherList.append(k ^ PlainBytes[m])

    return keystreamList, cipherList


def main(Filename="hex.txt", Action="decrypt", KeyName='key1.txt'):
    try:
        f = open(Filename, 'r')
        f.close()
        f = open(KeyName, 'r')
        f.close()
    except IOError:
        print('File(s) do not exist.\nUsage: RC4.py filename encrypt/decrypt [keyfile]')
    else:
        if Action == 'encrypt':
            Plain = Text(Filename)
            Key = Text(KeyName)
            Plain.encrypt(Key)
        elif Action == 'decrypt':
            Cipher = Text(Filename)
            Key = Text(KeyName)
            Cipher.decrypt(Key)
        else:
            print('Usage: RC4.py filename encrypt/decrypt [keyfile]')


if __name__ == '__main__':
    try:
        main()
    except TypeError:
        print('Usage: RC4.py filename encrypt/decrypt [keyfile]')

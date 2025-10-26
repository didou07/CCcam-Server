class CCcamCrypto:
    """CCcam encryption/decryption implementation"""
    
    def __init__(self):
        self.keytable = bytearray(256)
        self.state = 0
        self.counter = 0
        self.sum = 0
    
    def init(self, key: bytes):
        """Initialize crypto with key"""
        for i in range(256):
            self.keytable[i] = i
        
        j = 0
        for i in range(256):
            j = (j + key[i % len(key)] + self.keytable[i]) & 0xFF
            self.keytable[i], self.keytable[j] = self.keytable[j], self.keytable[i]
        
        self.state = key[0] if key else 0
        self.counter = 0
        self.sum = 0
    
    def crypt(self, data: bytearray, mode: int):
        """
        Encrypt or decrypt data in-place
        mode: 0 = decrypt, 1 = encrypt
        """
        for i in range(len(data)):
            self.counter = (self.counter + 1) & 0xFF
            self.sum = (self.sum + self.keytable[self.counter]) & 0xFF
            
            self.keytable[self.counter], self.keytable[self.sum] = \
                self.keytable[self.sum], self.keytable[self.counter]
            
            z = data[i]
            idx = (self.keytable[self.counter] + self.keytable[self.sum]) & 0xFF
            data[i] = z ^ self.keytable[idx] ^ self.state
            
            if mode == 0:
                z = data[i]
            
            self.state ^= z

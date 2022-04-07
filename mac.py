from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.py3compat import bord, _copy_bytes
from Crypto.Util.strxor import strxor

import enum
import hashlib

trans_5C = bytes((x ^ 0x5C) for x in range(256))
trans_36 = bytes((x ^ 0x36) for x in range(256))

def _shift_bytes(bs, xor_lsb = 0):
    num = (bytes_to_long(bs) << 1) ^ xor_lsb
    return long_to_bytes(num, len(bs))[-len(bs):]

@enum.unique
class Modes(enum.Enum):
    OMAC = 0,
    tMAC = 1,
    HMAC = 2

class MAC(object):
    def __init__(self):
        self.key = None
        self.mode = None
        self.block_size = None
        self.factory = None
        self.digest_cons = None
    
    def SetKey(self, key):
        self.key = _copy_bytes(None, None, key)
        self.block_size = AES.block_size
        self.factory = AES.new(self.key, AES.MODE_ECB)
        
        self.digest_cons = hashlib.sha256
    
    def SetMode(self, mode: Modes):
        self.mode = mode
        
        if self.mode == Modes.OMAC or self.mode == Modes.tMAC:
            self.__init_cmac()
        elif self.mode == Modes.HMAC:
            self.__init_hmac()
    
    def __init_cmac(self):
        self.cache = bytearray(self.block_size)
        self.last = None
    
    def __init_hmac(self):
        self.outer = self.digest_cons()
        self.inner = self.digest_cons()
        
        self.key = self.key.ljust(self.inner.block_size, b'\0')
        self.outer.update(self.key.translate(trans_5C))
        self.inner.update(self.key.translate(trans_36))
    
    def __pad(self, data_block):
        if len(data_block) == self.block_size:
            return data_block
        
        if self.mode == Modes.OMAC:
            return pad(data_block, self.block_size, style = 'iso7816')
        elif self.mode == Modes.tMAC:
            return pad(data_block, self.block_size)
    
    def __subkeys(self):
        if self.mode == Modes.OMAC or self.mode == Modes.tMAC:
            const_Rb = 0x87
        else:
            const_Rb = 0x1B
        
        zero_block = b'\x00' * self.block_size
        L = self.factory.encrypt(zero_block)
        if bord(L[0]) & 0x80:
            k1 = _shift_bytes(L, const_Rb)
        else:
            k1 = _shift_bytes(L)
        if bord(k1[0]) & 0x80:
            k2 = _shift_bytes(k1, const_Rb)
        else:
            k2 = _shift_bytes(k1)
        
        return k1, k2
    
    def MacAddBlock(self, data_block):
        if self.mode == Modes.OMAC or self.mode == Modes.tMAC:
            if self.last is not None:
                self.cache = self.factory.encrypt(strxor(bytes(self.cache), self.last))
            
            self.last = data_block
        elif self.mode == Modes.HMAC:
            self.inner.update(data_block)
    
    def MacFinalize(self):
        if self.mode == Modes.OMAC or self.mode == Modes.tMAC:
            k1, k2 = self.__subkeys()
            partial = self.__pad(self.last)
            
            if len(self.last) == self.block_size:
                mac_tag = self.factory.encrypt(strxor(strxor(partial, k1), bytes(self.cache)))
            else:
                mac_tag = self.factory.encrypt(strxor(partial, k2))
            
            self.__init_cmac()
            return mac_tag if self.mode == Modes.OMAC else mac_tag[:self.block_size // 2]
        elif self.mode == Modes.HMAC:
            h = self.outer.copy()
            h.update(self.inner.digest())
            self.__init_hmac()
            return h.digest()
    
    def ComputeMac(self, data):
        if self.mode == Modes.OMAC or self.mode == Modes.tMAC:
            mac_len = len(data) // self.block_size
            if len(data) % self.block_size != 0:
                mac_len += 1
            
            for i in range(mac_len - 1):
                self.MacAddBlock(data[i * self.block_size:][:self.block_size])
            
            self.MacAddBlock(data[(mac_len - 1) * self.block_size:])
        elif self.mode == Modes.HMAC:
            self.MacAddBlock(data)
        
        return self.MacFinalize()
    
    def VerifyMac(self, data, mac_tag):
        return self.ComputeMac(data) == (mac_tag if self.mode != Modes.tMAC else mac_tag[:self.block_size // 2])
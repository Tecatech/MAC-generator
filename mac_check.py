from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
import hashlib
import hmac
import sys
import time

from mac import *

def VerifyOmac():
    key = get_random_bytes(AES.block_size)
    data = get_random_bytes(int(2.5 * AES.block_size))
    
    cobj = CMAC.new(key, ciphermod = AES)
    cobj.update(data)
    
    mac = MAC()
    mac.SetKey(key)
    mac.SetMode(Modes.OMAC)
    
    assert mac.VerifyMac(data, cobj.digest())

def VerifyTmac():
    key = get_random_bytes(AES.block_size)
    data = get_random_bytes(int(2.5 * AES.block_size))
    
    cobj = CMAC.new(key, ciphermod = AES)
    cobj.update(data)
    
    mac = MAC()
    mac.SetKey(key)
    mac.SetMode(Modes.tMAC)
    
    assert mac.VerifyMac(data, cobj.digest())

def VerifyHmac():
    key = get_random_bytes(AES.block_size)
    data = get_random_bytes(int(2.5 * AES.block_size))
    
    obj = hmac.new(key, msg = data, digestmod = hashlib.sha256)
    
    mac = MAC()
    mac.SetKey(key)
    mac.SetMode(Modes.HMAC)
    
    assert mac.VerifyMac(data, obj.digest())

def timer(ComputeMac, data):
    start = time.perf_counter()
    ComputeMac(data)
    end = time.perf_counter()
    
    return end - start

def timing():
    mac_lens = [0.1, 1, 10, 1024]
    msg_num = 1000
    
    omac_graph = []
    hmac_graph = []
    
    for mac_len in mac_lens:
        omac_time = []
        hmac_time = []
        
        for _ in range(msg_num):
            data = get_random_bytes(int(mac_len * 1024))
            
            mac = MAC()
            mac.SetKey(get_random_bytes(AES.block_size))
            
            mac.SetMode(Modes.OMAC)
            omac_time.append(timer(mac.ComputeMac, data))
            
            mac.SetMode(Modes.HMAC)
            hmac_time.append(timer(mac.ComputeMac, data))
        
        omac_graph.append(sum(omac_time) / len(omac_time))
        hmac_graph.append(sum(hmac_time) / len(hmac_time))
    
    file = open('mac_plot.txt', 'w')
    sys.stdout = file
    
    print(*omac_graph, sep = ' ')
    print(*hmac_graph, sep = ' ')

if __name__ == '__main__':
    timing()
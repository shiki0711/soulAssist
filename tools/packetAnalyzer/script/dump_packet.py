import struct
import string
import sys

def unpackData(buff, l):
    bytesArray = ''
    for i in range(0, l, 2):
        hexStr = str(buff[i:i+2])
        bytesArray += (struct.pack('B',string.atoi(hexStr, 16)))
    return bytesArray

def transform(textfile, keyfile, ivfile, datafile):
    try:
        tfp = open(textfile, 'r')
        kfp = open(keyfile, 'wb')
        ifp = open(ivfile, 'wb')
        dfp = open(datafile, 'wb')
    except Exception:
        print 'Openfile error!'
        return -1

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    hdr1 = struct.unpack('<i', buf)[0]
    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    hdr2 = struct.unpack('<i', buf)[0]

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    keylen = struct.unpack('<i', buf)[0]
    buf = tfp.read(keylen*2)
    key = unpackData(buf, keylen*2)
    kfp.write(key)

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    ivlen = struct.unpack('<i', buf)[0]
    buf = tfp.read(ivlen*2)
    iv = unpackData(buf, ivlen*2)
    ifp.write(iv)
    
    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    datalen = struct.unpack('<i', buf)[0]
    buf = tfp.read(datalen*2)
    data = unpackData(buf, datalen*2)
    dfp.write(data)

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    sumlen = struct.unpack('<i', buf)[0]

    '''
    print hdr1
    print hdr2
    print keylen
    print ivlen
    print datalen
    print sumlen
    '''

if __name__ == '__main__':
    transform(sys.argv[1],  'key', 'iv', 'data')


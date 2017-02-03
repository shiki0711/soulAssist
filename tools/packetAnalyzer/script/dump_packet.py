import struct
import string
import sys

def unpackData(buff, l, strip0=False):
    bytesArray = ''
    for i in range(0, l, 2):
        hexStr = str(buff[i:i+2])
        if strip0 and hexStr == '00':
            continue
        bytesArray += (struct.pack('B',string.atoi(hexStr, 16)))
    return bytesArray

def transform(textfile, mode, keyfile, ivfile, datafile):
    try:
        tfp = open(textfile, 'r')
        kfp = open(keyfile, 'wb')
        ifp = open(ivfile, 'wb')
        dfp = open(datafile, 'wb')
    except Exception:
        print 'Openfile error!'
        return -1

    if mode == '-c':
        strip0 = True
        mul = 2
    else:
        strip0 = False
        mul = 2

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    hdr1 = struct.unpack('<i', buf)[0]
    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    hdr2 = struct.unpack('<i', buf)[0]

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    keylen = struct.unpack('<i', buf)[0]
    buf = tfp.read(keylen*mul)
    key = unpackData(buf, keylen*mul, strip0)
    kfp.write(key)

    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    ivlen = struct.unpack('<i', buf)[0]
    buf = tfp.read(ivlen*mul)
    iv = unpackData(buf, ivlen*mul, strip0)
    ifp.write(iv)

    if mode == '-r' or mode == '-c':
        buf = tfp.read(8)
    buf = tfp.read(8)
    buf = unpackData(buf, 8)
    datalen = struct.unpack('<i', buf)[0]
    buf = tfp.read(datalen*mul)
    data = unpackData(buf, datalen*mul, strip0)
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
    transform(sys.argv[1], sys.argv[2], 'key', 'iv', 'data')


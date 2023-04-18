import nimcrypto
import std/sysrand
import std/streams
import system

# nimAesCrypt version
let version: string = "0.1.0"

# default encryption/decryption buffer size - 64KB
let bufferSizeDef = 64 * 1024

# maximum password length (number of chars)
let maxPassLen = 1024

# AES block size in bytes
let AESBlockSize = 16

# password stretching function
proc stretch(passw: string, iv1: array[16, byte]): array[32, byte] =
    
    var digest: array[32, byte]
    copyMem(addr digest[0], unsafeAddr iv1[0], len(iv1))

    var passwBytes: array[1024, byte]
    copyMem(addr passwBytes[0], unsafeAddr passw[0], len(passw))
    
    for i in 1 .. 8192:
      var sha: sha256
      sha.init()
      sha.update(digest)  
      sha.update(passwBytes[0..len(passw)-1])
      digest = sha.finish().data

    return digest


# encrypt binary stream function
# arguments:
# fIn: input binary stream
# fOut: output binary stream
# passw: encryption password
# bufferSize: encryption buffer size, must be a multiple of
#             AES block size (16)
#             using a larger buffer speeds up things when dealing
#             with long streams
proc encryptStream*(fIn: Stream, fOut: Stream, passw: string, bufferSize: int) =

    # validate bufferSize
    if bufferSize mod AESBlockSize != 0:
        raise newException(OSError, "Buffer size must be a multiple of AES block size.")
    
    if len(passw) > maxPassLen:
        raise newException(OSError, "Password is too long.")

    # generate external iv (used to encrypt the main iv and the
    # encryption key)
    # let iv1 = urandom(AESBlockSize)
    let initIv1 = urandom(AESBlockSize)
    var iv1: array[16, byte]
    for i in [0..15]:
        iv1[i]=initIv1[i]
    
    # stretch password and iv
    let key = stretch(passw, iv1)
    
    # generate random main iv
    var iv0 = urandom(AESBlockSize)
    
    # generate random internal key
    var intKey = urandom(32)
    
    # instantiate AES cipher
    var encryptor0: CBC[aes256]
    encryptor0.init(intKey, iv0)
    
    # instantiate HMAC-SHA256 for the ciphertext
    var hmac0: HMAC[sha256]
    hmac0.init(intKey)

    # instantiate another AES cipher
    var encryptor1: CBC[aes256]
    encryptor1.init(key, iv1)
    
    # encrypt main iv and key
    var plainText = newString(len(iv0)+len(intKey))
    var c_iv_key = newString(len(iv0)+len(intKey))
    copyMem(addr plainText[0], unsafeAddr iv0[0], len(iv0))
    copyMem(addr plainText[0+len(iv0)], unsafeAddr intKey[0], len(intKey))
    encryptor1.encrypt(plainText, c_iv_key)
    
    # calculate HMAC-SHA256 of the encrypted iv and key
    var hmac1: HMAC[sha256]
    hmac1.init(key)
    hmac1.update(c_iv_key)

    # write header
    fOut.write("AES")
    
    # write version (AES Crypt version 2 file format -
    # see https://www.aescrypt.com/aes_file_format.html)
    fOut.write([byte 2])
    
    # reserved byte (set to zero)
    fOut.write([byte 0])
    
    # setup "CREATED-BY" extension
    var cby = "nimAesCrypt " & version

    # write "CREATED-BY" extension length
    fOut.write([byte 0, cast[uint8](1+len("CREATED_BY")+len(cby))])
        
    # write "CREATED-BY" extension
    fOut.write("CREATED_BY")
    fOut.write([byte 0])
    fOut.write(cby)
    
    # write "container" extension length
    fOut.write([byte 0, 128])
    
    # write "container" extension
    for i in 1 .. 128:
        fOut.write([byte 0])
        
    # write end-of-extensions tag
    fOut.write([byte 0, 0])
    
    # write the iv used to encrypt the main iv and the
    # encryption key
    fOut.write(iv1)
    
    # write encrypted main iv and key
    fOut.write(c_iv_key)
    
    # write HMAC-SHA256 of the encrypted iv and key
    fOut.write(hmac1.finish())
    
    var fs16 = 0
    # encrypt file while reading it
    var fdata = newString(bufferSize)
    var cText = newString(bufferSize)
    while true:
        # try to read bufferSize bytes
        let bytesRead = fIn.readData(addr fdata[0], bufferSize)
        
        # check if EOF was reached
        if bytesRead < bufferSize:
            # file size mod 16, lsb positions
            fs16 = bytesRead mod AESBlockSize
            # pad data (this is NOT PKCS#7!)
            # ...unless no bytes or a multiple of a block size
            # of bytes was read
            var padLen: int
            if bytesRead mod AESBlockSize == 0:
                padLen = 0
            else:
                padLen = 16 - bytesRead mod AESBlockSize

            # todo handl the pading to get the nb AES block & file with padLen, restrict the input of encrypt to x block
#             fdata += bytes([padLen])*padLen
            for i in bytesRead..bytesRead+padLen:
                fdata[i]=cast[char](padLen)
                
            # encrypt data
            encryptor0.encrypt(fdata[0..bytesRead+padLen-1], cText)

            # update HMAC
            hmac0.update(cText[0..bytesRead+padLen-1])
            # write encrypted file content
            fOut.write(cText[0..bytesRead+padLen-1])
            break
        # ...otherwise a full bufferSize was read
        else:
            # encrypt data
            encryptor0.encrypt(fdata, cText)          
            # update HMAC
            hmac0.update(cText)
            # write encrypted file content
            fOut.write(cText)
    
    # write plaintext file size mod 16 lsb positions
    fOut.write(cast[uint8](fs16))
    
    # write HMAC-SHA256 of the encrypted file
    fOut.write(hmac0.finish())


# encrypt file function
# arguments:
# infile: plaintext file path
# outfile: ciphertext file path
# passw: encryption password
# bufferSize: optional buffer size, must be a multiple of
#             AES block size (16)
#             using a larger buffer speeds up things when dealing
#             with big files
#             Default is 64KB.
proc encryptFile*(infile: string, outfile: string, passw: string, bufferSize: int = bufferSizeDef) =
    try:
        let fIn =  newFileStream(infile, mode = fmRead)
        defer: fIn.close()

        let fOut = newFileStream(outfile, mode = fmWrite)
        defer: fOut.close()

        encryptStream(fIn, fOut, passw, bufferSize)
                
    except CatchableError:
        let
            e = getCurrentException()
            msg = getCurrentExceptionMsg()
        echo "Inside checkIn, got exception ", repr(e), " with message ", msg


# decrypt stream function
# arguments:
# fIn: input binary stream
# fOut: output binary stream
# passw: encryption password
# bufferSize: decryption buffer size, must be a multiple of AES block size (16)
#             using a larger buffer speeds up things when dealing with
#             long streams
# inputLength: input stream length
proc decryptStream*(fIn: Stream, fOut: Stream, passw: string, bufferSize: int, inputLength: int64) =
    # validate bufferSize
    if bufferSize mod AESBlockSize != 0:
        raise newException(OSError, "Buffer size must be a multiple of AES block size")
    
    if len(passw) > maxPassLen:
        raise newException(OSError, "Password is too long.")
    
    var aesBuff: array[4, char]
    var nbBytesRead = fIn.readData(addr(aesBuff), 3)

    # check if file is in AES Crypt format (also min length check)
    if (aesBuff[0..2] != "AES" or inputLength < 136):
            raise newException(OSError, "File is corrupted or not an AES Crypt (or nimAesCrypt) file.")
        
    # check if file is in AES Crypt format, version 2
    # (the only one compatible with nimAesCrypt)
    var buffer: array[1024, byte]
    nbBytesRead = fIn.readData(addr(buffer), 1)
    if nbBytesRead != 1:
        raise newException(OSError, "File is corrupted.")
    
    if buffer[0] != cast[uint8](2):
        raise newException(OSError, "nimAesCrypt is only compatible with version 2 of the AES Crypt file format.")
    
    # skip reserved byte
    nbBytesRead = fIn.readData(addr(buffer), 1)
    
    # skip all the extensions
    while true:
        nbBytesRead = fIn.readData(addr(buffer), 2)
        if nbBytesRead != 2:
            raise newException(OSError, "File is corrupted.")
        if buffer[0..1] == [byte 0,0]:
            break
        var nbBytesToRead = cast[int16](buffer[1])
        nbBytesRead = fIn.readData(addr(buffer), nbBytesToRead)
        
    # read external iv
    var iv1: array[16, byte]
    nbBytesRead = fIn.readData(addr(iv1), 16)
    if nbBytesRead != 16:
        raise newException(OSError, "File is corrupted.")
    
    # stretch password and iv
    let key = stretch(passw, iv1)
    
    # read encrypted main iv and key
    var c_iv_key: array[48, byte]
    nbBytesRead = fIn.readData(addr(c_iv_key), 48)
    if nbBytesRead != 48:
        raise newException(OSError, "File is corrupted.")
        
    # read HMAC-SHA256 of the encrypted iv and key
    var hmac1: array[32, byte]
    nbBytesRead = fIn.readData(addr(hmac1), 32)
    if nbBytesRead != 32:
        raise newException(OSError, "File is corrupted.")
    
    # compute actual HMAC-SHA256 of the encrypted iv and key
    var hmac1Act: HMAC[sha256]
    hmac1Act.init(key)
    hmac1Act.update(c_iv_key)

    # HMAC check
    if hmac1 != hmac1Act.finish().data:
        raise newException(OSError, "Wrong password (or file is corrupted).")
    
    # instantiate AES cipher
    var decryptor1: CBC[aes256]
    decryptor1.init(key, iv1)
    
    # decrypt main iv and key
    var iv_key: array[48, byte]
    decryptor1.decrypt(addr c_iv_key[0], addr iv_key[0], 48)
    
    # get internal iv and key
    var iv0: array[16, byte]
    for i in 0..15:
        iv0[i]=iv_key[i]
        
    var intKey: array[32, byte]
    for i in 0..31:
        intKey[i]=iv_key[16+i]
    
    # instantiate another AES cipher
    var decryptor0: CBC[aes256]
    decryptor0.init(intKey, iv0)
    
    # instantiate actual HMAC-SHA256 of the ciphertext
    var hmac0Act: HMAC[sha256]
    hmac0Act.init(intKey)

    # decrypt ciphertext, until last block is reached
    var cText = newString(bufferSize)
    var decryptedBytes = newString(bufferSize)
    while fIn.getPosition() < inputLength - 32 - 1 - AESBlockSize:
        # read data
        nbBytesRead = fIn.readData(addr(cText[0]), cast[int](min(bufferSize, inputLength - fIn.getPosition() - 32 - 1 - AESBlockSize)))
        # update HMAC
        hmac0Act.update(cast[ptr byte](addr cText[0]), cast[uint](nbBytesRead))
        # decrypt data and write it to output file
        decryptor0.decrypt(cast[ptr byte](addr cText[0]), cast[ptr byte](addr decryptedBytes[0]), cast[uint](nbBytesRead))
        fOut.writeData(addr (decryptedBytes[0]), nbBytesRead)
        
    # last block reached, remove padding if needed
    
    # read last block
    
    # this is for empty files
    var finalBlockSize=0
    var finalCText = newString(AESBlockSize)
    if fIn.getPosition() != inputLength - 32 - 1:
        finalBlockSize = fIn.readData(addr(finalCText[0]), AESBlockSize)
        if finalBlockSize < AESBlockSize:
            raise newException(OSError, "File is corrupted.")
    
    # update HMAC
    hmac0Act.update(finalCText)

    # decrypt last block
    var pText = newString(AESBlockSize)
    decryptor0.decrypt(finalCText, pText)

    # read plaintext file size mod 16 lsb positions
    nbBytesRead = fIn.readData(addr(buffer), 1)
    var fs16 = cast[int16](buffer[0])
    if nbBytesRead != 1:
        raise newException(OSError, "File is corrupted.")
        
    # remove padding
    var toremove = ((16 - fs16) mod 16)        

    # write decrypted data to output file
    fOut.writeData(addr pText[0], finalBlockSize-toremove)
    
    # read HMAC-SHA256 of the encrypted file
    var hmac0: array[32, byte]
    nbBytesRead = fIn.readData(addr(hmac0), 32)
    if nbBytesRead != 32:
        raise newException(OSError, "File is corrupted.")
    
    # HMAC check
    if hmac0 != hmac0Act.finish().data:
        raise newException(OSError, "Bad HMAC (file is corrupted).")   


# decrypt file function
# arguments:
# infile: ciphertext file path
# outfile: plaintext file path
# passw: encryption password
# bufferSize: optional buffer size, must be a multiple of AES block size (16)
#             using a larger buffer speeds up things when dealing with
#             big files
#             Default is 64KB.
proc decryptFile*(infile: string, outfile: string, passw: string, bufferSize: int = bufferSizeDef) =
    try:
        let fIn =  newFileStream(infile, mode = fmRead)
        defer: fIn.close()

        let fOut = newFileStream(outfile, mode = fmWrite)
        defer: fOut.close()

        let fInSize =  open(infile, mode = fmRead)
        var fileSize = getFileSize(fInSize)
        fInSize.close()

        decryptStream(fIn, fOut, passw, bufferSize, fileSize)
                
    except CatchableError:
        let
            e = getCurrentException()
            msg = getCurrentExceptionMsg()
        echo "Inside checkIn, got exception ", repr(e), " with message ", msg
                  
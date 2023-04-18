import ../nimAesCrypt
import os
import std/streams
import std/sysrand
import std/strformat


proc test(fileSize: int) = 
    let fOut = newFileStream(fmt"testsNimAesCrypt/test{$fileSize}.txt", mode = fmWrite)

    var randData = urandom(fileSize)
    fOut.writeData(addr (randData[0]), fileSize)
    fOut.close()

    encryptFile(fmt"testsNimAesCrypt/test{$fileSize}.txt", fmt"testsNimAesCrypt/test{$fileSize}.aes", "foopassword!1$A", 1024)

    decryptFile(fmt"testsNimAesCrypt/test{$fileSize}.aes", fmt"testsNimAesCrypt/test{$fileSize}.dec.txt", "foopassword!1$A", 1024)

    let fInit = open(fmt"testsNimAesCrypt/test{$fileSize}.txt")
    var stringInit = newString(fileSize)
    stringInit = fInit.readall()
    let fFinal = open(fmt"testsNimAesCrypt/test{$fileSize}.dec.txt")
    var stringFinal = newString(fileSize)
    stringFinal = fFinal.readall()

    assert(stringFinal == stringInit)


proc main() =
    createDir("testsNimAesCrypt")

    test(1)
    test(16)
    test(21)
    test(32)
    test(55)
    test(1024)
    test(1024*10+20)

    echo "[+] All tests succeed"

main()
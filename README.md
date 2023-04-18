# nimAesCrypt

## About nimAesCrypt  

nimAesCrypt is a reimplementation of [pyAesCrypt](https://github.com/marcobellaccini/pyAesCrypt) in nim.  
nimAesCrypt is a nim file-encryption module that uses AES256-CBC to encrypt/decrypt files.  
 
## Module usage example  

Here is an example showing encryption and decryption of a file:  

```nim
    import nimAesCrypt
    encryptFile("file.txt", "file.aes", "long-and-random-password", 1024)
    decryptFile("file.aes", "fileDecrypt.txt", "long-and-random-password", 1024)
```




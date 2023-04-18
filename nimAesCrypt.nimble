# Package

version     = "0.1.0"
author      = "Maxime de Caumia Baillenx"
description = "Nim file-encryption module that uses AES256-CBC to encrypt/decrypt files."
license     = "Apache 2.0"

# Dependencies

requires "nim > 0.18.0"
requires "nimcrypto"

# Tests

task tests, "Run tests":
  exec("nim c -f -r -d:nimAesCryptTests tests/test_crypto.nim")

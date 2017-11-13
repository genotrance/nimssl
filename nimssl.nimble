# Package

version       = "0.1.0"
author        = "genotrance"
description   = "OpenSSL wrapper for Nim"
license       = "MIT"

skipDirs = @["tests"]

# Dependencies

requires "nimgen >= 0.1.0"

import distros

var cmd = ""
if detectOs(Windows):
    cmd = "cmd /c "

task nimgen, "Run nimgen":
    exec cmd & "nimgen nimssl.cfg"

task reset, "Reset git":
    withDir("nimssl"):
        exec "git reset --hard HEAD"

task setup, "Checkout and build OpenSSL":
    if dirExists("nimssl"):
        resetTask()
    else:
        exec "git init nimssl"
        withDir("nimssl"):
            exec "git remote add origin https://github.com/openssl/openssl.git"
            exec "git config core.sparsecheckout true"
            exec cmd & "echo include/* >> .git/info/sparse-checkout"
            exec cmd & "echo crypto/* >> .git/info/sparse-checkout"
            exec "git pull --depth=1 origin master"

    nimgenTask()

    resetTask()

before install:
    setupTask()

task test, "Run tests":
    withDir("tests"):
        exec "nim c -r shatest"
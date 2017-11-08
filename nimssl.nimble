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

task checkout, "Checkout OpenSSL":
    if dirExists("nimssl"):
        withDir("nimssl"):
            exec "git reset --hard HEAD"
    else:
        exec "git init nimssl"
        withDir("nimssl"):
            exec "git remote add origin https://github.com/openssl/openssl.git"
            exec "git config core.sparsecheckout true"
            exec cmd & "echo include/* >> .git/info/sparse-checkout"
            exec cmd & "echo crypto/* >> .git/info/sparse-checkout"
            exec "git pull --depth=1 origin master"

task nimgen, "Run nimgen":
    exec cmd & "nimgen nimssl.cfg"

before install:
    checkoutTask()

    nimgenTask()

task test, "Run tests":
    withDir("tests"):
        exec "nim c -r shatest"
# Package

version       = "0.1.1"
author        = "genotrance"
description   = "OpenSSL wrapper for Nim"
license       = "MIT"

skipDirs = @["tests"]

# Dependencies

requires "nimgen >= 0.1.1"

import distros

var cmd = ""
if detectOs(Windows):
    cmd = "cmd /c "

task setup, "Checkout and generate":
    exec cmd & "nimgen nimssl.cfg"

before install:
    setupTask()

task test, "Run tests":
    withDir("tests"):
        exec "nim c -r shatest"
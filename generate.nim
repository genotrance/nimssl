import osproc
import strutils
import sequtils
import os

var fp = commandLineParams()[2]

if "import os" notin readFile(fp):

  var core = """
import os

import nimterop/[build, cimport]

static:
  cDebug()
  cSkipSymbol @["filler"] # Skips

getHeader("openssl/""" & commandLineParams()[0] & """")
const basePath = cryptoPath.parentDir

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'}).replace("__", "_")

    # Replacements here

type
  tmp = object
  # Objects here

# Starts"""

  for i in ($readFile(commandLineParams()[1])).strip(chars={'\n'}).split("\n"):
    core = core & "\ncImport(basePath/\"" & i.split("/")[^1] & "\", dynlib=\"cryptoLPath\")"

  writeFile(fp, core)

while true:
  var r = execProcess("nim c -d:sslStd -d:cryptoStd -r " & fp)

  if "Error: undeclared identifier: " in r.split("\n")[^2]:

    var text = readFile(fp)
    var problem = r.split("\n")[^2].split("'")[^2]

    echo problem
    if "  " & problem & " = object" notin text:

      var tmp = @(text.split("\n"))
      tmp.insert(@["  " & problem & " = object"], tmp.find("  # Objects here"))

      writeFile(fp, tmp.join("\n").replace("] # Skips", ",\"" & problem & "\"] # Skips"))

  elif " is a stylistic duplicate of identifier " in r.split("\n")[^2]:
    var t1 = r.split("\n")[^2].split("'")[1]
    var t2 = r.split("\n")[^2].split("'")[3]

    var text = readFile(fp)
    var tmp = @(text.split("\n"))
    tmp.insert(@["    if sym.name == \"" & t1 & "\":", "      sym.name = \"" & t2 & "\""], tmp.find("    # Replacements here"))
    writeFile(fp, tmp.join("\n"))

  else:
    echo r
    break

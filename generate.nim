import osproc
import strutils
import sequtils
import os
import re

let base = "/usr/include/openssl"

var res: seq[string] = @[]

proc process(file: string, parent = "", depth = "") =
  let file = file.extractFilename()
  if not fileExists(base / file):
    return

  #echo depth & "Processing " & file

  let data = readFile(base / file)
  for inc in data.findAll(re"#[ ]*include[ ]?<(.*?)>"):
    var inc = inc.replace(re"#[ ]*include[ ]?<", "")[0 .. ^2]
    if "openssl" in inc:
      inc = inc[8 .. ^1]

      if inc == parent:
        continue

      if inc notin res:
        process(inc, file, depth & "  ")

  if file notin res:
    if parent.len == 0:
     #echo depth & "Adding " & file
     res.add file
    else:
     let idx = res.find(parent)
     if idx != -1:
       #echo depth & "Adding dep " & file
       res.insert(file, idx)
     else:
       #echo depth & "Appending dep " & file
       res.add file

var fp = commandLineParams()[2]

if "import os" notin readFile(fp):

  var core = """
import os

import nimterop/[build, cimport]

static:
  cDebug()
  cSkipSymbol @["filler"] # Skips

getHeader("openssl/""" & commandLineParams()[0] & """")
const basePath = """ & commandLineParams()[0].split(".")[0] & """Path.parentDir

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'}).replace("__", "_")

    # Replacements here

type
  tmp = object
  # Objects here

# Starts
"""

  for file in walkFiles(base / "*.h"):
    process(file)

  let tmp = ($readFile(commandLineParams()[1])).strip(chars={'\n'}).split("\n")
  for i in res:
    if i in tmp:
      core.add("""
when fileExists(basePath/"$1"):
  cImport(basePath/"$1", dynlib="$2Path")
""" % @[i, commandLineParams()[0].split(".")[0]])

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

      writeFile(fp, tmp.join("\n"))

  elif " is a stylistic duplicate of identifier " in r.split("\n")[^2]:
    var t1 = r.split("\n")[^2].split("'")[1]
    var t2 = r.split("\n")[^2].split("'")[3]

    var text = readFile(fp)
    var tmp = @(text.split("\n"))
    tmp.insert(@["    if sym.name == \"" & t2 & "\":", "      sym.name = \"C_" & t2 & "\""], tmp.find("    # Replacements here"))
    writeFile(fp, tmp.join("\n"))

  elif "redefinition of" in r.split("\n")[^2]:
    var t1 = r.split("\n")[^2].split("'")[1]
    var text = readFile(fp)
    writeFile(fp, text.replace("] # Skips", ",\"" & t1 & "\"] # Skips"))

  else:
    echo r
    break

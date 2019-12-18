import nimssl/crypto
import strutils

# Test input and output
var test = "hello"
let hashSHA1 = "AAF4C61DDCC5E8A2DABEDE0F3B482CD9AEA9434D"
let hashSHA224 = "EA09AE9CC6768C50FCEE903ED054556E5BFC8347907F12598AA24193"
let hashSHA256 = "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824"
let hashSHA384 = "59E1748777448C69DE6B800D7A33BBFB9FF1B463E44354C3553BCDB9C666FA90125A3C79F90397BDF5F6A13DE828684F"
let hashSHA512 = "9B71D224BD62F3785D96D46AD3EA3D73319BFBC2890CAADAE2DFF72519673CA72323C3D99BA5C11D7C7ACC6E14B8C5DA0C4663475C2E5C3ADEF46F73BCDEC043"

# Verify results match
assert SHA1(addr test[0], cast[uint](test.len()), nil).toArray(20).toHex() == hashSHA1
assert SHA224(addr test[0], cast[uint](test.len()), nil).toArray(28).toHex() == hashSHA224
assert SHA256(addr test[0], cast[uint](test.len()), nil).toArray(32).toHex() == hashSHA256
assert SHA384(addr test[0], cast[uint](test.len()), nil).toArray(48).toHex() == hashSHA384
assert SHA512(addr test[0], cast[uint](test.len()), nil).toArray(64).toHex() == hashSHA512

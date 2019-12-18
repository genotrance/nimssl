import nimssl/crypto

var
  e: culong = 0x10001
  r = RSA_new()
  bn = BN_new()

doAssert bn.BN_set_word(e) == 1

# The assumption is made here that because generating a private key is a
# more complex task then all other RSA procs, and that it relies on all
# of the features that other RSA procs do, then it is a fair test for
# the RSA part of libcrypto overal.
doAssert RSA_generate_key_ex(r, 1024.cint, bn, nil) == 1

bn.BN_free()
r.RSA_free()

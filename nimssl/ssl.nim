import os

import nimterop/[build, cimport]

static:
  cDebug()
  cSkipSymbol @["filler"] # Skips

getHeader("openssl/ssl.h")
const basePath = sslPath.parentDir

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'}).replace("__", "_")

    if sym.name == "BF_ENCRYPT":
      sym.name = "C_BF_ENCRYPT"
    if sym.name == "BF_DECRYPT":
      sym.name = "C_BF_DECRYPT"
    # Replacements here

type
  tmp = object
  asn1_string_st = object
  asn1_object_st = object
  ASN1_ITEM_st = object
  asn1_pctx_st = object
  asn1_sctx_st = object
  bio_st = object
  bignum_st = object
  bignum_ctx = object
  bn_blinding_st = object
  bn_mont_ctx_st = object
  bn_recp_ctx_st = object
  bn_gencb_st = object
  buf_mem_st = object
  evp_cipher_st = object
  evp_cipher_ctx_st = object
  evp_md_st = object
  evp_md_ctx_st = object
  evp_pkey_st = object
  evp_pkey_asn1_method_st = object
  evp_pkey_method_st = object
  evp_pkey_ctx_st = object
  evp_Encode_Ctx_st = object
  hmac_ctx_st = object
  dh_st = object
  dh_method = object
  dsa_st = object
  dsa_method = object
  rsa_st = object
  rsa_meth_st = object
  ec_key_st = object
  ec_key_method_st = object
  rand_meth_st = object
  rand_drbg_st = object
  ssl_dane_st = object
  x509_st = object
  X509_algor_st = object
  X509_crl_st = object
  x509_crl_method_st = object
  x509_revoked_st = object
  X509_name_st = object
  X509_pubkey_st = object
  x509_store_st = object
  x509_store_ctx_st = object
  x509_object_st = object
  x509_lookup_st = object
  x509_lookup_method_st = object
  X509_VERIFY_PARAM_st = object
  x509_sig_info_st = object
  pkcs8_priv_key_info_st = object
  v3_ext_ctx = object
  conf_st = object
  ossl_init_settings_st = object
  ui_st = object
  ui_method_st = object
  engine_st = object
  ssl_st = object
  ssl_ctx_st = object
  comp_ctx_st = object
  comp_method_st = object
  X509_POLICY_NODE_st = object
  X509_POLICY_LEVEL_st = object
  X509_POLICY_TREE_st = object
  X509_POLICY_CACHE_st = object
  AUTHORITY_KEYID_st = object
  DIST_POINT_st = object
  ISSUING_DIST_POINT_st = object
  NAME_CONSTRAINTS_st = object
  crypto_ex_data_st = object
  ocsp_req_ctx_st = object
  ocsp_response_st = object
  ocsp_responder_id_st = object
  sct_st = object
  sct_ctx_st = object
  ctlog_st = object
  ctlog_store_st = object
  ct_policy_eval_ctx_st = object
  ossl_store_info_st = object
  ossl_store_search_st = object
  stack_st_X509 = object
  ssl_method_st = object
  ssl_cipher_st = object
  ssl_session_st = object
  tls_sigalgs_st = object
  ssl_conf_ctx_st = object
  ssl_comp_st = object
  stack_st_SCT = object
  lhash_st_SSL_SESSION = object
  pem_password_cb = object
  BIO_METHOD = object
  stack_st_X509_NAME = object
  BIO_ADDR = object
  # Objects here

# Starts
when fileExists(basePath/"opensslv.h"):
  cImport(basePath/"opensslv.h", dynlib="sslPath")
when fileExists(basePath/"opensslconf.h"):
  cImport(basePath/"opensslconf.h", dynlib="sslPath")
when fileExists(basePath/"e_os2.h"):
  cImport(basePath/"e_os2.h", dynlib="sslPath")
when fileExists(basePath/"safestack.h"):
  cImport(basePath/"safestack.h", dynlib="sslPath")
when fileExists(basePath/"ossl_typ.h"):
  cImport(basePath/"ossl_typ.h", dynlib="sslPath")
when fileExists(basePath/"symhacks.h"):
  cImport(basePath/"symhacks.h", dynlib="sslPath")
when fileExists(basePath/"ebcdic.h"):
  cImport(basePath/"ebcdic.h", dynlib="sslPath")
when fileExists(basePath/"blowfish.h"):
  cImport(basePath/"blowfish.h", dynlib="sslPath")
when fileExists(basePath/"obj_mac.h"):
  cImport(basePath/"obj_mac.h", dynlib="sslPath")
when fileExists(basePath/"dtls1.h"):
  cImport(basePath/"dtls1.h", dynlib="sslPath")
when fileExists(basePath/"sslerr.h"):
  cImport(basePath/"sslerr.h", dynlib="sslPath")
when fileExists(basePath/"ssl2.h"):
  cImport(basePath/"ssl2.h", dynlib="sslPath")
when fileExists(basePath/"ssl3.h"):
  cImport(basePath/"ssl3.h", dynlib="sslPath")
when fileExists(basePath/"tls1.h"):
  cImport(basePath/"tls1.h", dynlib="sslPath")
when fileExists(basePath/"ssl.h"):
  cImport(basePath/"ssl.h", dynlib="sslPath")

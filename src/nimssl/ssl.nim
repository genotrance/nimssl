import os

import nimterop/[build, cimport]

static:
  cDebug()
  cSkipSymbol @["filler","cryptoPath","asn1_string_st","asn1_object_st","ASN1_ITEM_st","asn1_pctx_st","asn1_sctx_st","bio_st","bignum_st","bignum_ctx","bn_blinding_st","bn_mont_ctx_st","bn_recp_ctx_st","bn_gencb_st","buf_mem_st","evp_cipher_st","evp_cipher_ctx_st","evp_md_st","evp_md_ctx_st","evp_pkey_st","evp_pkey_asn1_method_st","evp_pkey_method_st","evp_pkey_ctx_st","evp_Encode_Ctx_st","hmac_ctx_st","dh_st","dh_method","dsa_st","dsa_method","rsa_st","rsa_meth_st","ec_key_st","ec_key_method_st","rand_meth_st","rand_drbg_st","ssl_dane_st","x509_st","X509_algor_st","X509_crl_st","x509_crl_method_st","x509_revoked_st","X509_name_st","X509_pubkey_st","x509_store_st","x509_store_ctx_st","x509_object_st","x509_lookup_st","x509_lookup_method_st","X509_VERIFY_PARAM_st","x509_sig_info_st","pkcs8_priv_key_info_st","v3_ext_ctx","conf_st","ossl_init_settings_st","ui_st","ui_method_st","engine_st","ssl_st","ssl_ctx_st","comp_ctx_st","comp_method_st","X509_POLICY_NODE_st","X509_POLICY_LEVEL_st","X509_POLICY_TREE_st","X509_POLICY_CACHE_st","AUTHORITY_KEYID_st","DIST_POINT_st","ISSUING_DIST_POINT_st","NAME_CONSTRAINTS_st","crypto_ex_data_st","ocsp_req_ctx_st","ocsp_response_st","ocsp_responder_id_st","sct_st","sct_ctx_st","ctlog_st","ctlog_store_st","ct_policy_eval_ctx_st","ossl_store_info_st","ossl_store_search_st","tls_session_ticket_ext_st","ssl_method_st","ssl_cipher_st","ssl_session_st","tls_sigalgs_st","ssl_conf_ctx_st","ssl_comp_st","SSL","SSL_CIPHER","X509","X509_STORE_CTX","SSL_SESSION","EVP_MD","SSL_COMP","CT_POLICY_EVAL_CTX","stack_st_SCT","SSL_CTX","lhash_st_SSL_SESSION","ENGINE","BIO","pem_password_cb","BIO_METHOD","SSL_METHOD","X509_STORE","RSA","EVP_PKEY","stack_st_X509","stack_st_X509_NAME","SSL_DANE","X509_VERIFY_PARAM","BIGNUM","COMP_METHOD","SSL_CONF_CTX","BIO_ADDR","CTLOG_STORE","OPENSSL_INIT_SETTINGS"] # Skips

getHeader("openssl/ssl.h")
const basePath = sslPath.parentDir

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'}).replace("__", "_")

    if sym.name == "BF_encrypt":
      sym.name = "BF_ENCRYPT"
    if sym.name == "BF_decrypt":
      sym.name = "BF_DECRYPT"
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
  tls_session_ticket_ext_st = object
  ssl_method_st = object
  ssl_cipher_st = object
  ssl_session_st = object
  tls_sigalgs_st = object
  ssl_conf_ctx_st = object
  ssl_comp_st = object
  SSL = object
  SSL_CIPHER = object
  X509 = object
  X509_STORE_CTX = object
  SSL_SESSION = object
  EVP_MD = object
  SSL_COMP = object
  CT_POLICY_EVAL_CTX = object
  stack_st_SCT = object
  SSL_CTX = object
  lhash_st_SSL_SESSION = object
  ENGINE = object
  BIO = object
  pem_password_cb = object
  BIO_METHOD = object
  SSL_METHOD = object
  X509_STORE = object
  RSA = object
  EVP_PKEY = object
  stack_st_X509 = object
  stack_st_X509_NAME = object
  SSL_DANE = object
  X509_VERIFY_PARAM = object
  BIGNUM = object
  COMP_METHOD = object
  SSL_CONF_CTX = object
  BIO_ADDR = object
  CTLOG_STORE = object
  OPENSSL_INIT_SETTINGS = object
  # Objects here

  # Starts
cImport(basePath/"blowfish.h", dynlib="sslLPath")
cImport(basePath/"dtls1.h", dynlib="sslLPath")
cImport(basePath/"e_os2.h", dynlib="sslLPath")
cImport(basePath/"ebcdic.h", dynlib="sslLPath")
cImport(basePath/"obj_mac.h", dynlib="sslLPath")
cImport(basePath/"opensslconf.h", dynlib="sslLPath")
cImport(basePath/"opensslv.h", dynlib="sslLPath")
cImport(basePath/"ossl_typ.h", dynlib="sslLPath")
cImport(basePath/"safestack.h", dynlib="sslLPath")
cImport(basePath/"ssl.h", dynlib="sslLPath")
cImport(basePath/"ssl2.h", dynlib="sslLPath")
cImport(basePath/"ssl3.h", dynlib="sslLPath")
cImport(basePath/"sslerr.h", dynlib="sslLPath")
cImport(basePath/"symhacks.h", dynlib="sslLPath")
cImport(basePath/"tls1.h", dynlib="sslLPath")

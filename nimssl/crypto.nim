import os
import strutils

import nimterop/[build, cimport]

static:
  cDebug()
  cSkipSymbol @["filler","ASN1_TEMPLATE_st","ASN1_TLC_st","EVP_Cipher","X509_algor_st","stack_st_X509_ATTRIBUTE","stack_st_X509","stack_st_X509_CRL","stack_st_POLICYQUALINFO","stack_st_X509_POLICY_NODE"] # Skips

getHeader("openssl/crypto.h")
const basePath = cryptoPath.parentDir

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'}).replace("__", "_")

    if sym.name == "AES_ENCRYPT":
      sym.name = "C_AES_ENCRYPT"
    if sym.name == "AES_DECRYPT":
      sym.name = "C_AES_DECRYPT"
    if sym.name == "OpenSSL_version":
      sym.name = "C_OpenSSL_version"
    if sym.name == "CRYPTO_THREADID":
      sym.name = "C_CRYPTO_THREADID"
    if sym.name == "BIO_CTRL_PENDING":
      sym.name = "C_BIO_CTRL_PENDING"
    if sym.name == "BIO_CTRL_WPENDING":
      sym.name = "C_BIO_CTRL_WPENDING"
    if sym.name == "BN_F_BNRAND":
      sym.name = "C_BN_F_BNRAND"
    if sym.name == "BN_F_BNRAND_RANGE":
      sym.name = "C_BN_F_BNRAND_RANGE"
    if sym.name == "CAMELLIA_ENCRYPT":
      sym.name = "C_CAMELLIA_ENCRYPT"
    if sym.name == "CAMELLIA_DECRYPT":
      sym.name = "C_CAMELLIA_DECRYPT"
    if sym.name == "CAST_ENCRYPT":
      sym.name = "C_CAST_ENCRYPT"
    if sym.name == "CAST_DECRYPT":
      sym.name = "C_CAST_DECRYPT"
    if sym.name == "PKCS7_ENCRYPT":
      sym.name = "C_PKCS7_ENCRYPT"
    if sym.name == "X509V3_EXT_D2I":
      sym.name = "C_X509V3_EXT_D2I"
    if sym.name == "X509V3_EXT_I2D":
      sym.name = "C_X509V3_EXT_I2D"
    if sym.name == "IDEA_ENCRYPT":
      sym.name = "C_IDEA_ENCRYPT"
    if sym.name == "OCSP_cert_id_new":
      sym.name = "C_OCSP_cert_id_new"
    if sym.name == "OCSP_crlID_new":
      sym.name = "C_OCSP_crlID_new"
    if sym.name == "RC2_ENCRYPT":
      sym.name = "C_RC2_ENCRYPT"
    if sym.name == "RC2_DECRYPT":
      sym.name = "C_RC2_DECRYPT"
    if sym.name == "OSSL_STORE_SEARCH_BY_NAME":
      sym.name = "C_OSSL_STORE_SEARCH_BY_NAME"
    if sym.name == "OSSL_STORE_SEARCH_BY_ISSUER_SERIAL":
      sym.name = "C_OSSL_STORE_SEARCH_BY_ISSUER_SERIAL"
    if sym.name == "OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT":
      sym.name = "C_OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT"
    if sym.name == "OSSL_STORE_SEARCH_BY_ALIAS":
      sym.name = "C_OSSL_STORE_SEARCH_BY_ALIAS"
    # Replacements here

type
  tmp = object
  stack_st = object
  CRYPTO_EX_DATA = object
  pthread_once_t = object
  pthread_key_t = object
  pthread_t = object
  tm = object
  OPENSSL_INIT_SETTINGS = object
  bio_addr_st = object
  bio_addrinfo_st = object
  BIO = object
  bio_method_st = object
  hostent = object
  BIGNUM = object
  BN_GENCB = object
  BN_CTX = object
  BN_MONT_CTX = object
  BN_BLINDING = object
  BN_RECP_CTX = object
  X509_ALGOR = object
  ASN1_TEMPLATE_st = object
  ASN1_TLC_st = object
  ASN1_VALUE_st = object
  ASN1_ITEM = object
  ASN1_INTEGER = object
  ASN1_GENERALSTRING = object
  ASN1_UTF8STRING = object
  ASN1_TYPE = object
  ASN1_OBJECT = object
  ASN1_STRING = object
  ASN1_BIT_STRING = object
  ASN1_ENUMERATED = object
  ASN1_UTCTIME = object
  ASN1_GENERALIZEDTIME = object
  ASN1_TIME = object
  ASN1_OCTET_STRING = object
  ASN1_VISIBLESTRING = object
  ASN1_UNIVERSALSTRING = object
  ASN1_NULL = object
  ASN1_BMPSTRING = object
  ASN1_PRINTABLESTRING = object
  ASN1_T61STRING = object
  ASN1_IA5STRING = object
  CONF = object
  X509V3_CTX = object
  ASN1_PCTX = object
  ASN1_SCTX = object
  ASN1_TEMPLATE = object
  ASN1_TLC = object
  async_job_st = object
  async_wait_ctx_st = object
  BUF_MEM = object
  camellia_key_st = object
  EVP_CIPHER = object
  EVP_CIPHER_CTX = object
  EVP_MD = object
  EVP_PKEY_CTX = object
  EVP_MD_CTX = object
  ENGINE = object
  EVP_PKEY = object
  EVP_ENCODE_CTX = object
  EVP_PKEY_ASN1_METHOD = object
  EVP_PKEY_METHOD = object
  CMAC_CTX_st = object
  ec_method_st = object
  ec_group_st = object
  ec_point_st = object
  ecpk_parameters_st = object
  ec_parameters_st = object
  ECDSA_SIG_st = object
  EC_KEY = object
  EC_KEY_METHOD = object
  RSA = object
  RSA_METHOD = object
  DH = object
  DH_METHOD = object
  DSA_SIG_st = object
  DSA = object
  DSA_METHOD = object
  SHA256_CTX = object
  SHA512_CTX = object
  lhash_node_st = object
  lhash_st = object
  X509_LOOKUP = object
  X509_OBJECT = object
  X509_VERIFY_PARAM = object
  X509_STORE_CTX = object
  X509 = object
  X509_CRL = object
  X509_NAME = object
  stack_st_X509 = object
  stack_st_X509_CRL = object
  X509_STORE = object
  X509_LOOKUP_METHOD = object
  X509_POLICY_TREE = object
  SSL_DANE = object
  X509_POLICY_LEVEL = object
  stack_st_X509_POLICY_NODE = object
  X509_POLICY_NODE = object
  stack_st_POLICYQUALINFO = object
  stack_st_X509_ATTRIBUTE = object
  pkcs7_st = object
  PKCS7 = object
  X509_STORE_CTX_lookup_certs_fn = object
  X509_STORE_CTX_lookup_crls_fn = object
  X509_sig_st = object
  X509_name_entry_st = object
  X509_extension_st = object
  x509_attributes_st = object
  X509_req_info_st = object
  X509_req_st = object
  x509_cert_aux_st = object
  x509_cinf_st = object
  X509_REVOKED = object
  X509_crl_info_st = object
  X509_PUBKEY = object
  X509_CRL_METHOD = object
  OCSP_REQ_CTX = object
  PKCS8_PRIV_KEY_INFO = object
  X509_SIG_INFO = object
  conf_imodule_st = object
  conf_module_st = object
  GENERAL_NAME = object
  DIST_POINT_NAME = object
  DIST_POINT = object
  POLICYQUALINFO = object
  ASIdOrRange = object
  ASIdentifierChoice = object
  IPAddressOrRange = object
  IPAddressChoice = object
  NamingAuthority_st = object
  ProfessionInfo_st = object
  Admissions_st = object
  AdmissionSyntax_st = object
  AUTHORITY_KEYID = object
  ISSUING_DIST_POINT = object
  NAME_CONSTRAINTS = object
  stack_st_OPENSSL_STRING = object
  CMS_ContentInfo_st = object
  CMS_SignerInfo_st = object
  CMS_RevocationInfoChoice_st = object
  CMS_RecipientInfo_st = object
  CMS_ReceiptRequest_st = object
  CMS_Receipt_st = object
  CMS_RecipientEncryptedKey_st = object
  CMS_OtherKeyAttribute_st = object
  COMP_METHOD = object
  COMP_CTX = object
  SCT = object
  CTLOG = object
  CT_POLICY_EVAL_CTX = object
  CTLOG_STORE = object
  DES_key_schedule = object
  RAND_METHOD = object
  ui_string_st = object
  UI = object
  UI_METHOD = object
  SSL = object
  ENGINE_CTRL_FUNC_PTR = object
  HMAC_CTX = object
  IDEA_KEY_SCHEDULE = object
  gcm128_context = object
  ccm128_context = object
  xts128_context = object
  ocb128_context = object
  ocb128_f = object
  ocsp_cert_id_st = object
  ocsp_one_request_st = object
  ocsp_req_info_st = object
  ocsp_signature_st = object
  ocsp_request_st = object
  ocsp_resp_bytes_st = object
  OCSP_RESPID = object
  ocsp_revoked_info_st = object
  ocsp_cert_status_st = object
  ocsp_single_response_st = object
  ocsp_response_data_st = object
  ocsp_basic_response_st = object
  ocsp_crl_id_st = object
  ocsp_service_locator_st = object
  OCSP_RESPONSE = object
  PKCS12_MAC_DATA_st = object
  PKCS12_st = object
  PKCS12_SAFEBAG_st = object
  pkcs12_bag_st = object
  RAND_DRBG = object
  SSL_CTX = object
  stack_st_SRTP_PROTECTION_PROFILE = object
  SRTP_PROTECTION_PROFILE = object
  ossl_store_ctx_st = object
  OSSL_STORE_INFO = object
  ossl_store_loader_st = object
  ossl_store_loader_ctx_st = object
  OSSL_STORE_SEARCH = object
  # Objects here
  lhash_st_ERR_STRING_DATA = object
  lhash_st_CONF_VALUE = object

# Starts
when fileExists(basePath/"aes.h"):
  cImport(basePath/"aes.h", dynlib="cryptoLPath")
when fileExists(basePath/"stack.h"):
  cImport(basePath/"stack.h", dynlib="cryptoLPath")
when fileExists(basePath/"cryptoerr.h"):
  cImport(basePath/"cryptoerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"crypto.h"):
  cImport(basePath/"crypto.h", dynlib="cryptoLPath")
when fileExists(basePath/"bioerr.h"):
  cImport(basePath/"bioerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"bio.h"):
  cImport(basePath/"bio.h", dynlib="cryptoLPath")
when fileExists(basePath/"asn1err.h"):
  cImport(basePath/"asn1err.h", dynlib="cryptoLPath")
when fileExists(basePath/"bnerr.h"):
  cImport(basePath/"bnerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"bn.h"):
  cImport(basePath/"bn.h", dynlib="cryptoLPath")
when fileExists(basePath/"asn1.h"):
  cImport(basePath/"asn1.h", dynlib="cryptoLPath")
when fileExists(basePath/"asn1t.h"):
  cImport(basePath/"asn1t.h", dynlib="cryptoLPath")
when fileExists(basePath/"asyncerr.h"):
  cImport(basePath/"asyncerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"async.h"):
  cImport(basePath/"async.h", dynlib="cryptoLPath")
when fileExists(basePath/"buffererr.h"):
  cImport(basePath/"buffererr.h", dynlib="cryptoLPath")
when fileExists(basePath/"buffer.h"):
  cImport(basePath/"buffer.h", dynlib="cryptoLPath")
when fileExists(basePath/"camellia.h"):
  cImport(basePath/"camellia.h", dynlib="cryptoLPath")
when fileExists(basePath/"cast.h"):
  cImport(basePath/"cast.h", dynlib="cryptoLPath")
when fileExists(basePath/"evperr.h"):
  cImport(basePath/"evperr.h", dynlib="cryptoLPath")
when fileExists(basePath/"objectserr.h"):
  cImport(basePath/"objectserr.h", dynlib="cryptoLPath")
when fileExists(basePath/"objects.h"):
  cImport(basePath/"objects.h", dynlib="cryptoLPath")
when fileExists(basePath/"evp.h"):
  cImport(basePath/"evp.h", dynlib="cryptoLPath")
when fileExists(basePath/"cmac.h"):
  cImport(basePath/"cmac.h", dynlib="cryptoLPath")
when fileExists(basePath/"ecerr.h"):
  cImport(basePath/"ecerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"ec.h"):
  cImport(basePath/"ec.h", dynlib="cryptoLPath")
when fileExists(basePath/"rsaerr.h"):
  cImport(basePath/"rsaerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"rsa.h"):
  cImport(basePath/"rsa.h", dynlib="cryptoLPath")
when fileExists(basePath/"dherr.h"):
  cImport(basePath/"dherr.h", dynlib="cryptoLPath")
when fileExists(basePath/"dh.h"):
  cImport(basePath/"dh.h", dynlib="cryptoLPath")
when fileExists(basePath/"dsaerr.h"):
  cImport(basePath/"dsaerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"dsa.h"):
  cImport(basePath/"dsa.h", dynlib="cryptoLPath")
when fileExists(basePath/"sha.h"):
  cImport(basePath/"sha.h", dynlib="cryptoLPath")
when fileExists(basePath/"x509err.h"):
  cImport(basePath/"x509err.h", dynlib="cryptoLPath")
when fileExists(basePath/"lhash.h"):
  cImport(basePath/"lhash.h", dynlib="cryptoLPath")
when fileExists(basePath/"x509_vfy.h"):
  cImport(basePath/"x509_vfy.h", dynlib="cryptoLPath")
when fileExists(basePath/"pkcs7err.h"):
  cImport(basePath/"pkcs7err.h", dynlib="cryptoLPath")
when fileExists(basePath/"pkcs7.h"):
  cImport(basePath/"pkcs7.h", dynlib="cryptoLPath")
when fileExists(basePath/"x509.h"):
  cImport(basePath/"x509.h", dynlib="cryptoLPath")
when fileExists(basePath/"conferr.h"):
  cImport(basePath/"conferr.h", dynlib="cryptoLPath")
when fileExists(basePath/"conf.h"):
  cImport(basePath/"conf.h", dynlib="cryptoLPath")
when fileExists(basePath/"x509v3err.h"):
  cImport(basePath/"x509v3err.h", dynlib="cryptoLPath")
when fileExists(basePath/"x509v3.h"):
  cImport(basePath/"x509v3.h", dynlib="cryptoLPath")
when fileExists(basePath/"cmserr.h"):
  cImport(basePath/"cmserr.h", dynlib="cryptoLPath")
when fileExists(basePath/"cms.h"):
  cImport(basePath/"cms.h", dynlib="cryptoLPath")
when fileExists(basePath/"comperr.h"):
  cImport(basePath/"comperr.h", dynlib="cryptoLPath")
when fileExists(basePath/"comp.h"):
  cImport(basePath/"comp.h", dynlib="cryptoLPath")
when fileExists(basePath/"conf_api.h"):
  cImport(basePath/"conf_api.h", dynlib="cryptoLPath")
when fileExists(basePath/"cterr.h"):
  cImport(basePath/"cterr.h", dynlib="cryptoLPath")
when fileExists(basePath/"ct.h"):
  cImport(basePath/"ct.h", dynlib="cryptoLPath")
when fileExists(basePath/"des.h"):
  cImport(basePath/"des.h", dynlib="cryptoLPath")
when fileExists(basePath/"ecdh.h"):
  cImport(basePath/"ecdh.h", dynlib="cryptoLPath")
when fileExists(basePath/"ecdsa.h"):
  cImport(basePath/"ecdsa.h", dynlib="cryptoLPath")
when fileExists(basePath/"randerr.h"):
  cImport(basePath/"randerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"rand.h"):
  cImport(basePath/"rand.h", dynlib="cryptoLPath")
when fileExists(basePath/"pemerr.h"):
  cImport(basePath/"pemerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"pem.h"):
  cImport(basePath/"pem.h", dynlib="cryptoLPath")
when fileExists(basePath/"uierr.h"):
  cImport(basePath/"uierr.h", dynlib="cryptoLPath")
when fileExists(basePath/"ui.h"):
  cImport(basePath/"ui.h", dynlib="cryptoLPath")
when fileExists(basePath/"err.h"):
  cImport(basePath/"err.h", dynlib="cryptoLPath")
when fileExists(basePath/"engineerr.h"):
  cImport(basePath/"engineerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"engine.h"):
  cImport(basePath/"engine.h", dynlib="cryptoLPath")
when fileExists(basePath/"hmac.h"):
  cImport(basePath/"hmac.h", dynlib="cryptoLPath")
when fileExists(basePath/"idea.h"):
  cImport(basePath/"idea.h", dynlib="cryptoLPath")
when fileExists(basePath/"kdferr.h"):
  cImport(basePath/"kdferr.h", dynlib="cryptoLPath")
when fileExists(basePath/"kdf.h"):
  cImport(basePath/"kdf.h", dynlib="cryptoLPath")
when fileExists(basePath/"md2.h"):
  cImport(basePath/"md2.h", dynlib="cryptoLPath")
when fileExists(basePath/"mdc2.h"):
  cImport(basePath/"mdc2.h", dynlib="cryptoLPath")
when fileExists(basePath/"modes.h"):
  cImport(basePath/"modes.h", dynlib="cryptoLPath")
when fileExists(basePath/"ocsperr.h"):
  cImport(basePath/"ocsperr.h", dynlib="cryptoLPath")
when fileExists(basePath/"ocsp.h"):
  cImport(basePath/"ocsp.h", dynlib="cryptoLPath")
when fileExists(basePath/"pem2.h"):
  cImport(basePath/"pem2.h", dynlib="cryptoLPath")
when fileExists(basePath/"pkcs12err.h"):
  cImport(basePath/"pkcs12err.h", dynlib="cryptoLPath")
when fileExists(basePath/"pkcs12.h"):
  cImport(basePath/"pkcs12.h", dynlib="cryptoLPath")
when fileExists(basePath/"rand_drbg.h"):
  cImport(basePath/"rand_drbg.h", dynlib="cryptoLPath")
when fileExists(basePath/"rc2.h"):
  cImport(basePath/"rc2.h", dynlib="cryptoLPath")
when fileExists(basePath/"rc4.h"):
  cImport(basePath/"rc4.h", dynlib="cryptoLPath")
when fileExists(basePath/"rc5.h"):
  cImport(basePath/"rc5.h", dynlib="cryptoLPath")
when fileExists(basePath/"seed.h"):
  cImport(basePath/"seed.h", dynlib="cryptoLPath")
when fileExists(basePath/"srp.h"):
  cImport(basePath/"srp.h", dynlib="cryptoLPath")
when fileExists(basePath/"srtp.h"):
  cImport(basePath/"srtp.h", dynlib="cryptoLPath")
when fileExists(basePath/"storeerr.h"):
  cImport(basePath/"storeerr.h", dynlib="cryptoLPath")
when fileExists(basePath/"store.h"):
  cImport(basePath/"store.h", dynlib="cryptoLPath")
when fileExists(basePath/"md4.h"):
  cImport(basePath/"md4.h", dynlib="cryptoLPath")
when fileExists(basePath/"md5.h"):
  cImport(basePath/"md5.h", dynlib="cryptoLPath")

# Cast digest into array
template toArray*(hash: untyped, dlen: int): untyped =
    cast[ptr array[dlen, char]](hash)

# Convert array into hex
proc toHex*[T](hash: ptr T): string =
    result = ""
    for i in hash[]:
        result &= ($i).toHex()

    return result

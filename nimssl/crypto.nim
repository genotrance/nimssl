import os
import strutils

import nimterop/[build, cimport]

static:
  cDebug()
  cSkipSymbol @["filler","X509_ALGOR","ASN1_TEMPLATE_st","ASN1_TLC_st","ASN1_VALUE_st","ASN1_ITEM","ASN1_INTEGER","ASN1_GENERALSTRING","ASN1_UTF8STRING","ASN1_TYPE","ASN1_OBJECT","ASN1_STRING","ASN1_BIT_STRING","BIO","ASN1_ENUMERATED","ASN1_UTCTIME","ASN1_GENERALIZEDTIME","ASN1_TIME","ASN1_OCTET_STRING","ASN1_VISIBLESTRING","ASN1_UNIVERSALSTRING","ASN1_NULL","ASN1_BMPSTRING","ASN1_PRINTABLESTRING","ASN1_T61STRING","ASN1_IA5STRING","tm","BIGNUM","ASN1_VALUE","CONF","X509V3_CTX","ASN1_PCTX","ASN1_SCTX","ASN1_TEMPLATE","BIO_METHOD","ASN1_TLC","async_job_st","async_wait_ctx_st","ASYNC_WAIT_CTX","ASYNC_JOB","bio_addr_st","bio_addrinfo_st","BIO_ADDR","BIO_ADDRINFO","hostent","BN_GENCB","OPENSSL_CTX","BN_CTX","BN_MONT_CTX","CRYPTO_RWLOCK","BN_BLINDING","BN_RECP_CTX","BUF_MEM","camellia_key_st","CMAC_CTX_st","CMAC_CTX","EVP_CIPHER_CTX","EVP_CIPHER","ENGINE","CMS_ContentInfo_st","CMS_SignerInfo_st","CMS_RevocationInfoChoice_st","CMS_RecipientInfo_st","CMS_ReceiptRequest_st","CMS_Receipt_st","CMS_RecipientEncryptedKey_st","CMS_OtherKeyAttribute_st","CMS_SignerInfo","CMS_RecipientEncryptedKey","CMS_RecipientInfo","CMS_RevocationInfoChoice","CMS_ContentInfo","CMS_ReceiptRequest","X509","EVP_PKEY","stack_st_X509","EVP_MD","X509_STORE","EVP_PKEY_CTX","X509_NAME","X509_CRL","stack_st_X509_CRL","EVP_MD_CTX","X509_ATTRIBUTE","stack_st_GENERAL_NAMES","CMS_OtherKeyAttribute","COMP_METHOD","COMP_CTX","conf_imodule_st","conf_module_st","CONF_MODULE","CONF_IMODULE","CRYPTO_EX_DATA","pthread_once_t","pthread_key_t","OPENSSL_INIT_SETTINGS","CRYPTO_THREAD_LOCAL","SCT","CTLOG","CT_POLICY_EVAL_CTX","CTLOG_STORE","DES_key_schedule","DH","DH_METHOD","DSA_SIG_st","DSA","DSA_SIG","DSA_METHOD","ec_method_st","ec_group_st","ec_point_st","ecpk_parameters_st","ec_parameters_st","ECDSA_SIG_st","EC_METHOD","EC_GROUP","EC_POINT","ECPARAMETERS","ECPKPARAMETERS","EC_KEY","EC_KEY_METHOD","ECDSA_SIG","SSL","stack_st_X509_NAME","UI_METHOD","EVP_PKEY_METHOD","EVP_PKEY_ASN1_METHOD","RSA_METHOD","RAND_METHOD","ENGINE_CTRL_FUNC_PTR","ENGINE_LOAD_KEY_PTR","ERR_STATE","OSSL_PROVIDER","OSSL_PARAM","EVP_ENCODE_CTX","EVP_MAC","EVP_MAC_CTX","EVP_KEYMGMT","EVP_SIGNATURE","EVP_ASYM_CIPHER","EVP_KEYEXCH","HMAC_CTX","IDEA_KEY_SCHEDULE","EVP_KDF","EVP_KDF_CTX","lhash_node_st","lhash_st","OPENSSL_LHASH","gcm128_context","ccm128_context","xts128_context","ocb128_context","GCM128_CONTEXT","CCM128_CONTEXT","XTS128_CONTEXT","ocb128_f","OCB128_CONTEXT","ocsp_cert_id_st","OCSP_CERTID","ocsp_one_request_st","OCSP_ONEREQ","ocsp_req_info_st","ocsp_signature_st","ocsp_request_st","ocsp_resp_bytes_st","OCSP_RESPID","ocsp_revoked_info_st","ocsp_cert_status_st","ocsp_single_response_st","OCSP_SINGLERESP","ocsp_response_data_st","ocsp_basic_response_st","ocsp_crl_id_st","ocsp_service_locator_st","OCSP_REQUEST","OCSP_RESPONSE","OCSP_REQ_CTX","OCSP_BASICRESP","OCSP_RESPDATA","X509_EXTENSION","OCSP_CERTSTATUS","OCSP_REVOKEDINFO","OCSP_RESPBYTES","OCSP_SIGNATURE","OCSP_REQINFO","OCSP_CRLID","OCSP_SERVICELOC","pem_password_cb","stack_st_X509_INFO","X509_REQ","X509_PUBKEY","PKCS7","NETSCAPE_CERT_SEQUENCE","X509_SIG","PKCS8_PRIV_KEY_INFO","RSA","PKCS12_MAC_DATA_st","PKCS12_st","PKCS12_SAFEBAG_st","PKCS12_SAFEBAG","pkcs12_bag_st","PKCS12","stack_st_PKCS7","stack_st_X509_ATTRIBUTE","PKCS12_MAC_DATA","PKCS12_BAGS","pkcs7_st","X509_STORE_CTX","RAND_DRBG","RSA_PSS_PARAMS","SHA256_CTX","SHA512_CTX","stack_st_SRTP_PROTECTION_PROFILE","stack_st","OPENSSL_STACK","ossl_store_ctx_st","OSSL_STORE_INFO","ossl_store_loader_st","ossl_store_loader_ctx_st","OSSL_STORE_LOADER","OSSL_STORE_LOADER_CTX","OSSL_STORE_SEARCH","OSSL_STORE_post_process_info_fn","OSSL_STORE_CTX","OSSL_STORE_open_fn","OSSL_STORE_load_fn","TS_msg_imprint_st","TS_req_st","TS_accuracy_st","TS_tst_info_st","TS_status_info_st","TS_resp_st","ui_string_st","UI_STRING","UI"] # Skips

getHeader("openssl/crypto.h")
const basePath = cryptoPath.parentDir

cPlugin:
  import strutils

  proc onSymbol*(sym: var Symbol) {.exportc, dynlib.} =
    sym.name = sym.name.strip(chars = {'_'}).replace("__", "_")

    if sym.name == "AES_encrypt":
      sym.name = "AES_ENCRYPT"
    if sym.name == "AES_decrypt":
      sym.name = "AES_DECRYPT"
    if sym.name == "BIO_ctrl_pending":
      sym.name = "BIO_CTRL_PENDING"
    if sym.name == "BIO_ctrl_wpending":
      sym.name = "BIO_CTRL_WPENDING"
    if sym.name == "BN_F_BN_RAND":
      sym.name = "BN_F_BNRAND"
    if sym.name == "BN_F_BN_RAND_RANGE":
      sym.name = "BN_F_BNRAND_RANGE"
    if sym.name == "Camellia_encrypt":
      sym.name = "CAMELLIA_ENCRYPT"
    if sym.name == "Camellia_decrypt":
      sym.name = "CAMELLIA_DECRYPT"
    if sym.name == "CAST_encrypt":
      sym.name = "CAST_ENCRYPT"
    if sym.name == "CAST_decrypt":
      sym.name = "CAST_DECRYPT"
    if sym.name == "OPENSSL_VERSION":
      sym.name = "OpenSSL_version"
    if sym.name == "CRYPTO_THREAD_ID":
      sym.name = "CRYPTO_THREADID"
    if sym.name == "EVP_Cipher":
      sym.name = "EVP_CIPHER"
    if sym.name == "IDEA_encrypt":
      sym.name = "IDEA_ENCRYPT"
    if sym.name == "OCSP_CERTID_new":
      sym.name = "OCSP_cert_id_new"
    if sym.name == "OCSP_CRLID_new":
      sym.name = "OCSP_crlID_new"
    if sym.name == "PKCS7_encrypt":
      sym.name = "PKCS7_ENCRYPT"
    if sym.name == "RC2_encrypt":
      sym.name = "RC2_ENCRYPT"
    if sym.name == "RC2_decrypt":
      sym.name = "RC2_DECRYPT"
    if sym.name == "OSSL_STORE_SEARCH_by_name":
      sym.name = "OSSL_STORE_SEARCH_BY_NAME"
    if sym.name == "OSSL_STORE_SEARCH_by_issuer_serial":
      sym.name = "OSSL_STORE_SEARCH_BY_ISSUER_SERIAL"
    if sym.name == "OSSL_STORE_SEARCH_by_key_fingerprint":
      sym.name = "OSSL_STORE_SEARCH_BY_KEY_FINGERPRINT"
    if sym.name == "OSSL_STORE_SEARCH_by_alias":
      sym.name = "OSSL_STORE_SEARCH_BY_ALIAS"
    if sym.name == "TS_RESP_CTX":
      sym.name = "TS_resp_ctx"
    # Replacements here

type
  tmp = object
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
  BIO = object
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
  tm = object
  BIGNUM = object
  ASN1_VALUE = object
  CONF = object
  X509V3_CTX = object
  ASN1_PCTX = object
  ASN1_SCTX = object
  ASN1_TEMPLATE = object
  BIO_METHOD = object
  ASN1_TLC = object
  async_job_st = object
  async_wait_ctx_st = object
  ASYNC_WAIT_CTX = object
  ASYNC_JOB = object
  bio_addr_st = object
  bio_addrinfo_st = object
  BIO_ADDR = object
  BIO_ADDRINFO = object
  hostent = object
  BN_GENCB = object
  OPENSSL_CTX = object
  BN_CTX = object
  BN_MONT_CTX = object
  CRYPTO_RWLOCK = object
  BN_BLINDING = object
  BN_RECP_CTX = object
  BUF_MEM = object
  camellia_key_st = object
  CMAC_CTX_st = object
  CMAC_CTX = object
  EVP_CIPHER_CTX = object
  EVP_CIPHER = object
  ENGINE = object
  CMS_ContentInfo_st = object
  CMS_SignerInfo_st = object
  CMS_RevocationInfoChoice_st = object
  CMS_RecipientInfo_st = object
  CMS_ReceiptRequest_st = object
  CMS_Receipt_st = object
  CMS_RecipientEncryptedKey_st = object
  CMS_OtherKeyAttribute_st = object
  CMS_SignerInfo = object
  CMS_RecipientEncryptedKey = object
  CMS_RecipientInfo = object
  CMS_RevocationInfoChoice = object
  CMS_ContentInfo = object
  CMS_ReceiptRequest = object
  X509 = object
  EVP_PKEY = object
  stack_st_X509 = object
  EVP_MD = object
  X509_STORE = object
  EVP_PKEY_CTX = object
  X509_NAME = object
  X509_CRL = object
  stack_st_X509_CRL = object
  EVP_MD_CTX = object
  X509_ATTRIBUTE = object
  stack_st_GENERAL_NAMES = object
  CMS_OtherKeyAttribute = object
  COMP_METHOD = object
  COMP_CTX = object
  conf_imodule_st = object
  conf_module_st = object
  CONF_MODULE = object
  CONF_IMODULE = object
  CRYPTO_EX_DATA = object
  pthread_once_t = object
  pthread_key_t = object
  OPENSSL_INIT_SETTINGS = object
  CRYPTO_THREAD_LOCAL = object
  SCT = object
  CTLOG = object
  CT_POLICY_EVAL_CTX = object
  CTLOG_STORE = object
  DES_key_schedule = object
  DH = object
  DH_METHOD = object
  DSA_SIG_st = object
  DSA = object
  DSA_SIG = object
  DSA_METHOD = object
  ec_method_st = object
  ec_group_st = object
  ec_point_st = object
  ecpk_parameters_st = object
  ec_parameters_st = object
  ECDSA_SIG_st = object
  EC_METHOD = object
  EC_GROUP = object
  EC_POINT = object
  ECPARAMETERS = object
  ECPKPARAMETERS = object
  EC_KEY = object
  EC_KEY_METHOD = object
  ECDSA_SIG = object
  SSL = object
  stack_st_X509_NAME = object
  UI_METHOD = object
  EVP_PKEY_METHOD = object
  EVP_PKEY_ASN1_METHOD = object
  RSA_METHOD = object
  RAND_METHOD = object
  ENGINE_CTRL_FUNC_PTR = object
  ENGINE_LOAD_KEY_PTR = object
  ERR_STATE = object
  OSSL_PROVIDER = object
  OSSL_PARAM = object
  EVP_ENCODE_CTX = object
  EVP_MAC = object
  EVP_MAC_CTX = object
  EVP_KEYMGMT = object
  EVP_SIGNATURE = object
  EVP_ASYM_CIPHER = object
  EVP_KEYEXCH = object
  HMAC_CTX = object
  IDEA_KEY_SCHEDULE = object
  EVP_KDF = object
  EVP_KDF_CTX = object
  lhash_node_st = object
  lhash_st = object
  OPENSSL_LHASH = object
  gcm128_context = object
  ccm128_context = object
  xts128_context = object
  ocb128_context = object
  GCM128_CONTEXT = object
  CCM128_CONTEXT = object
  XTS128_CONTEXT = object
  ocb128_f = object
  OCB128_CONTEXT = object
  ocsp_cert_id_st = object
  OCSP_CERTID = object
  ocsp_one_request_st = object
  OCSP_ONEREQ = object
  ocsp_req_info_st = object
  ocsp_signature_st = object
  ocsp_request_st = object
  ocsp_resp_bytes_st = object
  OCSP_RESPID = object
  ocsp_revoked_info_st = object
  ocsp_cert_status_st = object
  ocsp_single_response_st = object
  OCSP_SINGLERESP = object
  ocsp_response_data_st = object
  ocsp_basic_response_st = object
  ocsp_crl_id_st = object
  ocsp_service_locator_st = object
  OCSP_REQUEST = object
  OCSP_RESPONSE = object
  OCSP_REQ_CTX = object
  OCSP_BASICRESP = object
  OCSP_RESPDATA = object
  X509_EXTENSION = object
  OCSP_CERTSTATUS = object
  OCSP_REVOKEDINFO = object
  OCSP_RESPBYTES = object
  OCSP_SIGNATURE = object
  OCSP_REQINFO = object
  OCSP_CRLID = object
  OCSP_SERVICELOC = object
  pem_password_cb = object
  stack_st_X509_INFO = object
  X509_INFO = object
  X509_REQ = object
  X509_PUBKEY = object
  PKCS7 = object
  NETSCAPE_CERT_SEQUENCE = object
  X509_SIG = object
  PKCS8_PRIV_KEY_INFO = object
  RSA = object
  PKCS12_MAC_DATA_st = object
  PKCS12_st = object
  PKCS12_SAFEBAG_st = object
  PKCS12_SAFEBAG = object
  pkcs12_bag_st = object
  PKCS12 = object
  stack_st_PKCS7 = object
  stack_st_X509_ATTRIBUTE = object
  PKCS12_MAC_DATA = object
  PKCS12_BAGS = object
  pkcs7_st = object
  X509_STORE_CTX = object
  RAND_DRBG = object
  RSA_PSS_PARAMS = object
  SHA256_CTX = object
  SHA512_CTX = object
  SSL_CTX = object
  stack_st_SRTP_PROTECTION_PROFILE = object
  SRTP_PROTECTION_PROFILE = object
  stack_st = object
  OPENSSL_STACK = object
  ossl_store_ctx_st = object
  OSSL_STORE_INFO = object
  ossl_store_loader_st = object
  ossl_store_loader_ctx_st = object
  OSSL_STORE_LOADER = object
  OSSL_STORE_LOADER_CTX = object
  OSSL_STORE_SEARCH = object
  OSSL_STORE_post_process_info_fn = object
  OSSL_STORE_CTX = object
  OSSL_STORE_open_fn = object
  OSSL_STORE_load_fn = object
  TS_msg_imprint_st = object
  TS_req_st = object
  TS_accuracy_st = object
  TS_tst_info_st = object
  TS_status_info_st = object
  TS_resp_st = object
  ui_string_st = object
  UI_STRING = object
  UI = object
  lhash_st_CONF_VALUE = object
  lhash_st_ERR_STRING_DATA = object
  stack_st_OPENSSL_BLOCK = object
  STACK = object
  # Objects here

# Starts
cImport(basePath/"aes.h", dynlib="cryptoLPath")
cImport(basePath/"asn1.h", dynlib="cryptoLPath")
cImport(basePath/"asn1err.h", dynlib="cryptoLPath")
cImport(basePath/"asn1t.h", dynlib="cryptoLPath")
cImport(basePath/"async.h", dynlib="cryptoLPath")
cImport(basePath/"asyncerr.h", dynlib="cryptoLPath")
cImport(basePath/"bio.h", dynlib="cryptoLPath")
cImport(basePath/"bioerr.h", dynlib="cryptoLPath")
cImport(basePath/"bn.h", dynlib="cryptoLPath")
cImport(basePath/"bnerr.h", dynlib="cryptoLPath")
cImport(basePath/"buffer.h", dynlib="cryptoLPath")
cImport(basePath/"buffererr.h", dynlib="cryptoLPath")
cImport(basePath/"cast.h", dynlib="cryptoLPath")
cImport(basePath/"cmac.h", dynlib="cryptoLPath")
cImport(basePath/"cms.h", dynlib="cryptoLPath")
cImport(basePath/"cmserr.h", dynlib="cryptoLPath")
cImport(basePath/"comp.h", dynlib="cryptoLPath")
cImport(basePath/"comperr.h", dynlib="cryptoLPath")
cImport(basePath/"conf.h", dynlib="cryptoLPath")
cImport(basePath/"conf_api.h", dynlib="cryptoLPath")
cImport(basePath/"conferr.h", dynlib="cryptoLPath")
cImport(basePath/"crypto.h", dynlib="cryptoLPath")
cImport(basePath/"cryptoerr.h", dynlib="cryptoLPath")
cImport(basePath/"ct.h", dynlib="cryptoLPath")
cImport(basePath/"cterr.h", dynlib="cryptoLPath")
cImport(basePath/"des.h", dynlib="cryptoLPath")
cImport(basePath/"dh.h", dynlib="cryptoLPath")
cImport(basePath/"dherr.h", dynlib="cryptoLPath")
cImport(basePath/"dsa.h", dynlib="cryptoLPath")
cImport(basePath/"dsaerr.h", dynlib="cryptoLPath")
cImport(basePath/"ec.h", dynlib="cryptoLPath")
cImport(basePath/"ecdh.h", dynlib="cryptoLPath")
cImport(basePath/"ecdsa.h", dynlib="cryptoLPath")
cImport(basePath/"ecerr.h", dynlib="cryptoLPath")
cImport(basePath/"engine.h", dynlib="cryptoLPath")
cImport(basePath/"engineerr.h", dynlib="cryptoLPath")
cImport(basePath/"err.h", dynlib="cryptoLPath")
cImport(basePath/"evp.h", dynlib="cryptoLPath")
cImport(basePath/"evperr.h", dynlib="cryptoLPath")
cImport(basePath/"hmac.h", dynlib="cryptoLPath")
cImport(basePath/"idea.h", dynlib="cryptoLPath")
cImport(basePath/"kdf.h", dynlib="cryptoLPath")
cImport(basePath/"kdferr.h", dynlib="cryptoLPath")
cImport(basePath/"lhash.h", dynlib="cryptoLPath")
cImport(basePath/"md2.h", dynlib="cryptoLPath")
cImport(basePath/"mdc2.h", dynlib="cryptoLPath")
cImport(basePath/"modes.h", dynlib="cryptoLPath")
cImport(basePath/"objects.h", dynlib="cryptoLPath")
cImport(basePath/"objectserr.h", dynlib="cryptoLPath")
cImport(basePath/"ocsp.h", dynlib="cryptoLPath")
cImport(basePath/"ocsperr.h", dynlib="cryptoLPath")
cImport(basePath/"pem.h", dynlib="cryptoLPath")
cImport(basePath/"pem2.h", dynlib="cryptoLPath")
cImport(basePath/"pemerr.h", dynlib="cryptoLPath")
cImport(basePath/"pkcs12.h", dynlib="cryptoLPath")
cImport(basePath/"pkcs12err.h", dynlib="cryptoLPath")
cImport(basePath/"pkcs7.h", dynlib="cryptoLPath")
cImport(basePath/"pkcs7err.h", dynlib="cryptoLPath")
cImport(basePath/"rand.h", dynlib="cryptoLPath")
cImport(basePath/"rand_drbg.h", dynlib="cryptoLPath")
cImport(basePath/"randerr.h", dynlib="cryptoLPath")
cImport(basePath/"rc2.h", dynlib="cryptoLPath")
cImport(basePath/"rc4.h", dynlib="cryptoLPath")
cImport(basePath/"rc5.h", dynlib="cryptoLPath")
cImport(basePath/"rsa.h", dynlib="cryptoLPath")
cImport(basePath/"rsaerr.h", dynlib="cryptoLPath")
cImport(basePath/"seed.h", dynlib="cryptoLPath")
cImport(basePath/"sha.h", dynlib="cryptoLPath")
cImport(basePath/"srp.h", dynlib="cryptoLPath")
cImport(basePath/"srtp.h", dynlib="cryptoLPath")
cImport(basePath/"stack.h", dynlib="cryptoLPath")
cImport(basePath/"store.h", dynlib="cryptoLPath")
cImport(basePath/"storeerr.h", dynlib="cryptoLPath")
cImport(basePath/"ui.h", dynlib="cryptoLPath")
cImport(basePath/"uierr.h", dynlib="cryptoLPath")

# Cast digest into array
template toArray*(hash: untyped, dlen: int): untyped =
    cast[ptr array[dlen, char]](hash)

# Convert array into hex
proc toHex*[T](hash: ptr T): string =
    result = ""
    for i in hash[]:
        result &= ($i).toHex()

    return result

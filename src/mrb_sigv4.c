#include <mruby.h>
#include <mruby/string.h>
#include <sigv4.h>
#include <string.h>

static void MRB_SIGV4_ERR(mrb_state *mrb, const char *class) {
  struct RClass *AWS = mrb_module_get(mrb, "AWS");
  struct RClass *SigV4 = mrb_module_get_under(mrb, AWS, "SigV4");
  struct RClass *Error = mrb_class_get_under(mrb, SigV4, "Error");
  struct RClass *Class = mrb_class_get_under(mrb, Error, class);
  mrb_raisef(mrb, Class, "SigV4 responded with a %s code", class);
}

static void mrb_ensure_sigv4_success(mrb_state *mrb, SigV4Status_t status) {
  switch(status) {
    case SigV4Success: return;
    case SigV4InvalidParameter:           MRB_SIGV4_ERR(mrb, "InvalidParameter");
    case SigV4InsufficientMemory:         MRB_SIGV4_ERR(mrb, "InsufficientMemory");
    case SigV4ISOFormattingError:         MRB_SIGV4_ERR(mrb, "ISOFormattingError");
    case SigV4MaxHeaderPairCountExceeded: MRB_SIGV4_ERR(mrb, "MaxHeaderPairCountExceeded");
    case SigV4MaxQueryPairCountExceeded:  MRB_SIGV4_ERR(mrb, "MaxQueryPairCountExceeded");
    case SigV4HashError:                  MRB_SIGV4_ERR(mrb, "HashError");
    case SigV4InvalidHttpHeaders:         MRB_SIGV4_ERR(mrb, "InvalidHttpHeaders");
    default:                              MRB_SIGV4_ERR(mrb, "Error");
  }
}

struct hash_ctx {
  mrb_state *mrb;
  mrb_value digest; // instance of Digest::SHA256
};

int32_t mrb_digest_sha256_init( void * pHashContext ) {
  struct hash_ctx *ctx = pHashContext;
  struct RClass *Digest = mrb_module_get(ctx->mrb, "Digest");
  struct RClass *SHA2 = mrb_class_get_under(ctx->mrb, Digest, "SHA256");
  ctx->digest = mrb_obj_new(ctx->mrb, SHA2, 0, NULL);
  return 0;
}

int32_t mrb_digest_sha256_update( void * pHashContext,
                          const uint8_t * pInput,
                          size_t inputLen ) {
  struct hash_ctx *ctx = pHashContext;
  mrb_funcall(ctx->mrb, ctx->digest, "update", 1, mrb_str_new(ctx->mrb, (char *) pInput, inputLen));
  return 0;
}

int32_t mrb_digest_sha256_final( void * pHashContext,
                         uint8_t * pOutput,
                         size_t outputLen ) {
  struct hash_ctx *ctx = pHashContext;
  mrb_value digest = mrb_funcall(ctx->mrb, ctx->digest, "digest", 0);
  mrb_assert((mrb_int) outputLen >= RSTRING_LEN(digest));
  memcpy(pOutput, RSTRING_PTR(digest), RSTRING_LEN(digest));
  return 0;
}

static mrb_value mrb_sigv4_generate_signature(mrb_state *mrb, mrb_value self) {
  size_t auth_len = 2048U;
  mrb_value auth = mrb_str_new_capa(mrb, auth_len + 1);
  char *signature = NULL;
  size_t signature_len = 0;
  struct hash_ctx ctx = { .mrb = mrb, .digest = mrb_nil_value() };
  SigV4Credentials_t credentials = { 0 };
  SigV4Parameters_t sigv4info = { 0 };
  SigV4CryptoInterface_t crypto_interface = {
    .hashInit = mrb_digest_sha256_init,
    .hashUpdate = mrb_digest_sha256_update,
    .hashFinal = mrb_digest_sha256_final,
    .pHashContext = &ctx,
    .hashBlockLen = 64,
    .hashDigestLen = 32
  };
  SigV4HttpParameters_t http_params = { 0 };
#if MRUBY_RELEASE_MAJOR == 3
  mrb_sym kw_names[] = {
    mrb_intern_lit(mrb, "access_key_id"),
    mrb_intern_lit(mrb, "secret_access_key"),
    mrb_intern_lit(mrb, "region"),
    mrb_intern_lit(mrb, "service"),
    mrb_intern_lit(mrb, "time"),
    mrb_intern_lit(mrb, "request_method"),
    mrb_intern_lit(mrb, "request_path"),
    mrb_intern_lit(mrb, "request_query"),
    mrb_intern_lit(mrb, "request_headers"),
    mrb_intern_lit(mrb, "request_body")
  };
  const mrb_int kw_num = sizeof(kw_names) / sizeof(mrb_sym);
  const mrb_int kw_required = kw_num;
  mrb_value kw_values[kw_num];
  mrb_kwargs kwargs = { kw_num, kw_required, kw_names, kw_values, NULL };
#else
  const char *kw_names[] = {
    "access_key_id",
    "secret_access_key",
    "region",
    "service",
    "time",
    "request_method",
    "request_path",
    "request_query",
    "request_headers",
    "request_body",
  };
  const mrb_int kw_num = sizeof(kw_names) / sizeof(const char *);
  const mrb_int kw_required = kw_num;
  mrb_value kw_values[kw_num];
  mrb_kwargs kwargs = { kw_num, kw_values, kw_names, kw_required, NULL };
#endif
  mrb_get_args(mrb, ":", &kwargs);
  credentials.pAccessKeyId = RSTRING_PTR(kw_values[0]);
  credentials.accessKeyIdLen = RSTRING_LEN(kw_values[0]);
  credentials.pSecretAccessKey = RSTRING_PTR(kw_values[1]);
  credentials.secretAccessKeyLen = RSTRING_LEN(kw_values[1]);
  http_params.pHttpMethod = RSTRING_PTR(kw_values[5]);
  http_params.httpMethodLen = RSTRING_LEN(kw_values[5]);
  http_params.flags = 0; // Assume nothing about current request canonicalization. No optimization. TODO
  http_params.pPath = RSTRING_PTR(kw_values[6]);
  http_params.pathLen = RSTRING_LEN(kw_values[6]);
  http_params.pQuery = mrb_nil_p(kw_values[7]) ? NULL : RSTRING_PTR(kw_values[7]);
  http_params.queryLen = mrb_nil_p(kw_values[7]) ? 0 : RSTRING_LEN(kw_values[7]);
  http_params.pHeaders = RSTRING_PTR(kw_values[8]);
  http_params.headersLen = RSTRING_LEN(kw_values[8]);
  http_params.pPayload = RSTRING_PTR(kw_values[9]);
  http_params.payloadLen = RSTRING_LEN(kw_values[9]);
  sigv4info.pAlgorithm = SIGV4_AWS4_HMAC_SHA256;
  sigv4info.algorithmLen = SIGV4_AWS4_HMAC_SHA256_LENGTH;
  sigv4info.pCredentials = &credentials;
  sigv4info.pRegion = RSTRING_PTR(kw_values[2]);
  sigv4info.regionLen = RSTRING_LEN(kw_values[2]);
  sigv4info.pService = RSTRING_PTR(kw_values[3]);
  sigv4info.serviceLen = RSTRING_LEN(kw_values[3]);
  sigv4info.pDateIso8601 = mrb_str_to_cstr(mrb, kw_values[4]);
  sigv4info.pCryptoInterface = &crypto_interface;
  sigv4info.pHttpParameters = &http_params;
  SigV4Status_t rc = SigV4_GenerateHTTPAuthorization(&sigv4info,
                                                     RSTRING_PTR(auth),
                                                     &auth_len,
                                                     &signature,
                                                     &signature_len);
  mrb_ensure_sigv4_success(mrb, rc);
  struct RString *str = RSTRING(auth);
  RSTR_SET_LEN(str, auth_len);
  RSTR_PTR(str)[auth_len] = '\0';
  return auth;
}

void mrb_mruby_aws_sigv4_gem_init(mrb_state *mrb) {
  struct RClass *AWS = mrb_define_module(mrb, "AWS");
  struct RClass *SigV4 = mrb_define_module_under(mrb, AWS, "SigV4");
  struct RClass *Signer = mrb_define_class_under(mrb, SigV4, "Signer", mrb->object_class);
  mrb_define_method(mrb, Signer, "generate_signature", mrb_sigv4_generate_signature, MRB_ARGS_KEY(10, 0));
}

void mrb_mruby_aws_sigv4_gem_final(mrb_state *mrb) {
  (void) mrb; // unused
}

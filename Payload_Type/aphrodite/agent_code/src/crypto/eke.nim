## EKE — RSA-4096 key exchange for Mythic staging_rsa.
## OpenSSL RSA functions called via {.emit.}.
## Only compiled when -d:useEke is passed to the Nim compiler.

when defined(useEke):
  import std/[base64, random, strutils]

  {.emit: """
  #include <openssl/rsa.h>
  #include <openssl/pem.h>
  #include <openssl/bio.h>
  #include <openssl/err.h>
  #include <openssl/bn.h>
  """.}

  # ---------------------------------------------------------------------------
  # Low-level RSA wrappers
  # ---------------------------------------------------------------------------

  proc rsaGenerate2048(): int =
    ## Generate RSA-2048 key. Returns RSA* cast to int (0 on failure).
    var h: int
    {.emit: """
      BIGNUM *e = BN_new();
      BN_set_word(e, RSA_F4);
      RSA *rsa = RSA_new();
      if (RSA_generate_key_ex(rsa, 2048, e, NULL) <= 0) {
        RSA_free(rsa); rsa = NULL;
      }
      BN_free(e);
      `h` = (NI)(intptr_t)rsa;
    """.}
    result = h

  proc rsaFree(h: int) =
    {.emit: "if (`h`) RSA_free((RSA*)(intptr_t)`h`);".}

  proc rsaPublicKeyDer(h: int): string =
    ## Export SubjectPublicKeyInfo DER — readable by PyCryptodome RSA.import_key()
    var data: pointer
    var length: cint
    {.emit: """
      RSA *rsa = (RSA*)(intptr_t)`h`;
      unsigned char *buf = NULL;
      `length` = i2d_RSA_PUBKEY(rsa, &buf);
      `data` = (void*)buf;
    """.}
    if length <= 0: return ""
    result = newString(length)
    copyMem(addr result[0], data, length)
    {.emit: "OPENSSL_free(`data`);".}

  proc rsaDecrypt(h: int, enc: string): seq[byte] =
    ## RSA-OAEP decrypt (Mythic uses PKCS1_OAEP via PyCryptodome).
    if enc.len == 0: return @[]
    var outBuf = newSeq[byte](256)
    var outLen: cint
    let srcPtr = cast[pointer](unsafeAddr enc[0])
    let srcLen = cint(enc.len)
    let dstPtr = cast[pointer](addr outBuf[0])
    {.emit: """
      `outLen` = RSA_private_decrypt(
        `srcLen`, (const unsigned char*)`srcPtr`,
        (unsigned char*)`dstPtr`,
        (RSA*)(intptr_t)`h`, RSA_PKCS1_OAEP_PADDING);
    """.}
    if outLen <= 0:
      {.emit: """
        char _eke_err[256];
        ERR_error_string_n(ERR_get_error(), _eke_err, sizeof(_eke_err));
        fprintf(stderr, "[EKE] RSA decrypt error: %s (enc_len=%d)\n", _eke_err, (int)`srcLen`);
      """.}
      return @[]
    result = outBuf[0 ..< outLen]

  # ---------------------------------------------------------------------------
  # Public API
  # ---------------------------------------------------------------------------

  type EkaHandle* = object
    ## Opaque RSA key context.
    h: int

  proc ekaGenerate*(): EkaHandle =
    ## Generate a 2048-bit RSA key pair.
    result = EkaHandle(h: rsaGenerate2048())

  proc ekaIsValid*(ctx: EkaHandle): bool = ctx.h != 0

  proc ekaFree*(ctx: var EkaHandle) =
    rsaFree(ctx.h)
    ctx.h = 0

  proc ekaPublicKeyB64*(ctx: EkaHandle): string =
    ## Base64-encoded DER public key to send to Mythic in staging_rsa.
    let der = rsaPublicKeyDer(ctx.h)
    if der.len == 0: return ""
    result = base64.encode(der)

  proc ekaDecryptSessionKey*(ctx: EkaHandle, encB64: string): seq[byte] =
    ## Decrypt the AES session key Mythic sends back (RSA-OAEP).
    let enc = base64.decode(encB64)
    when defined(debug): stderr.writeLine("[EKE] encrypted key len=" & $enc.len & " (expected 256 for RSA-2048)")
    result = rsaDecrypt(ctx.h, enc)

  proc ekaSessionId*(): string =
    ## Generate a random 20-char hex session ID.
    randomize()
    const hex = "0123456789abcdef"
    result = ""
    for _ in 0 ..< 20:
      result.add(hex[rand(hex.len - 1)])

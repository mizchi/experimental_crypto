// Reference vectors for supported JWE algorithms.

///|
fn ref_jwe_b64u_to_bytes(s : String) -> Bytes {
  let buf = StringBuilder::new()
  for c in s {
    let c2 = if c == '-' { '+' } else if c == '_' { '/' } else { c }
    buf.write_char(c2)
  }
  let pad = (4 - s.length() % 4) % 4
  for _ in 0..<pad {
    buf.write_char('=')
  }
  @base64.decode(buf.to_string()) catch {
    _ => abort("bad base64url reference value")
  }
}

///|
test "RFC 7520 §5.6: direct A128GCM compact JWE decrypts" {
  // RFC 7520 Figures 130-136: alg=dir, enc=A128GCM.
  let cek = ref_jwe_b64u_to_bytes("XctOhJAkA-pD9Lh7ZgW_2A")
  let token = "eyJhbGciOiJkaXIiLCJraWQiOiI3N2M3ZTJiOC02ZTEzLTQ1Y2YtODY3Mi02MT" +
    "diNWI0NTI0M2EiLCJlbmMiOiJBMTI4R0NNIn0" +
    "." +
    "." +
    "refa467QzzKx6QAB" +
    "." +
    "JW_i_f52hww_ELQPGaYyeAB6HYGcR559l9TYnSovc23XJoBcW29rHP8yZOZG7Y" +
    "hLpT1bjFuvZPjQS-m0IFtVcXkZXdH_lr_FrdYt9HRUYkshtrMmIUAyGmUnd9zM" +
    "DB2n0cRDIHAzFVeJUDxkUwVAE7_YGRPdcqMyiBoCO-FBdE-Nceb4h3-FtBP-c_" +
    "BIwCPTjb9o0SbdcdREEMJMyZBH8ySWMVi1gPD9yxi-aQpGbSv_F9N4IZAxscj5" +
    "g-NJsUPbjk29-s7LJAGb15wEBtXphVCgyy53CoIKLHHeJHXex45Uz9aKZSRSIn" +
    "ZI-wjsY0yu3cT4_aQ3i1o-tiE-F8Ios61EKgyIQ4CWao8PFMj8TTnp" +
    "." +
    "vbb32Xvllea2OtmHAdccRQ"
  let expected = ref_jwe_b64u_to_bytes(
    "WW91IGNhbiB0cnVzdCB1cyB0byBzdGljayB3aXRoIHlvdSB0aHJvdWdoIHRoaWNrIGFuZCB0aGlu4oCTdG8gdGhlIGJpdHRlciBlbmQuIEFuZCB5b3UgY2FuIHRydXN0IHVzIHRvIGtlZXAgYW55IHNlY3JldCBvZiB5b3Vyc-KAk2Nsb3NlciB0aGFuIHlvdSBrZWVwIGl0IHlvdXJzZWxmLiBCdXQgeW91IGNhbm5vdCB0cnVzdCB1cyB0byBsZXQgeW91IGZhY2UgdHJvdWJsZSBhbG9uZSwgYW5kIGdvIG9mZiB3aXRob3V0IGEgd29yZC4gV2UgYXJlIHlvdXIgZnJpZW5kcywgRnJvZG8u",
  )
  let plaintext = @jwe.decrypt(token, @jwe.DecryptionKey::DecDir(cek~))
  @debug.assert_eq(plaintext, expected)
}

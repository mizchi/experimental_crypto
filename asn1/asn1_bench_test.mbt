// Benchmarks for the asn1 DER codec. Build with `moon bench --release`.

///|
fn build_flat_sequence(n : Int) -> @asn1.Element {
  let items : Array[@asn1.Element] = []
  for _ in 0..<n {
    items.push(
      @asn1.Element::new(
        @asn1.tag_integer,
        Integer(b"\x01\x02\x03\x04\x05\x06\x07\x08"),
      ),
    )
  }
  @asn1.Element::new(@asn1.tag_sequence, Sequence(items))
}

///|
fn build_nested_sequence(depth : Int) -> @asn1.Element {
  let mut inner = @asn1.Element::new(@asn1.tag_integer, Integer(b"\x2a"))
  for _ in 0..<depth {
    inner = @asn1.Element::new(@asn1.tag_sequence, Sequence([inner]))
  }
  inner
}

///|
test "bench asn1 encode flat SEQUENCE x100" (it : @bench.T) {
  let elem = build_flat_sequence(100)
  it.bench(fn() { it.keep(@asn1.encode_der(elem)) })
}

///|
test "bench asn1 decode flat SEQUENCE x100" (it : @bench.T) {
  let bytes = @asn1.encode_der(build_flat_sequence(100))
  it.bench(() => {
    it.keep(@asn1.decode_der(bytes) catch { _ => abort("unreachable") })
  })
}

///|
test "bench asn1 encode nested SEQUENCE depth=50" (it : @bench.T) {
  let elem = build_nested_sequence(50)
  it.bench(fn() { it.keep(@asn1.encode_der(elem)) })
}

///|
test "bench asn1 decode nested SEQUENCE depth=50" (it : @bench.T) {
  let bytes = @asn1.encode_der(build_nested_sequence(50))
  it.bench(() => {
    it.keep(@asn1.decode_der(bytes) catch { _ => abort("unreachable") })
  })
}

///|
test "bench asn1 oid from_string sha256WithRSAEncryption" (it : @bench.T) {
  it.bench(() => {
    it.keep(
      @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.11") catch {
        _ => abort("unreachable")
      },
    )
  })
}

///|
test "bench asn1 oid to_string sha256WithRSAEncryption" (it : @bench.T) {
  let oid = @asn1.ObjectIdentifier::from_string("1.2.840.113549.1.1.11")
  it.bench(fn() { it.keep(oid.to_string()) })
}

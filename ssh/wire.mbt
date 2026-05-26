// SSH binary wire format primitives (RFC 4251 §5).
//
// We only need the subset used by SSHSIG / sshsig.h + ssh-ed25519 public
// keys: `string` (uint32-length-prefixed bytes), `uint32`, and a fixed-size
// magic-preamble compare. mpint / boolean / name-list are not needed here.

///|
pub suberror SshError {
  TruncatedInput(String)
  InvalidEncoding(String)
  UnsupportedAlgorithm(String)
  PreambleMismatch
  UnsupportedSigVersion(UInt)
  HashAlgorithmMismatch(String)
  InvalidSignature
} derive(Show)

///|
// Mutable cursor over an SSH wire format buffer.
pub struct WireReader {
  buf : Bytes
  mut pos : Int
}

///|
pub fn WireReader::new(buf : Bytes) -> WireReader {
  { buf, pos: 0 }
}

///|
pub fn WireReader::remaining(self : WireReader) -> Int {
  self.buf.length() - self.pos
}

///|
pub fn WireReader::is_empty(self : WireReader) -> Bool {
  self.pos >= self.buf.length()
}

///|
pub fn WireReader::read_uint32(self : WireReader) -> UInt raise SshError {
  if self.remaining() < 4 {
    raise TruncatedInput("uint32")
  }
  let b0 = self.buf[self.pos].to_uint()
  let b1 = self.buf[self.pos + 1].to_uint()
  let b2 = self.buf[self.pos + 2].to_uint()
  let b3 = self.buf[self.pos + 3].to_uint()
  self.pos = self.pos + 4
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
pub fn WireReader::read_bytes(self : WireReader, n : Int) -> Bytes raise SshError {
  if self.remaining() < n {
    raise TruncatedInput("bytes(" + n.to_string() + ")")
  }
  let start = self.pos
  self.pos = self.pos + n
  Bytes::makei(n, fn(i) { self.buf[start + i] })
}

///|
// SSH `string`: uint32 length + that many bytes. Despite the name, used for
// binary blobs (pubkey contents, signature bytes) as well as ASCII strings.
pub fn WireReader::read_string(self : WireReader) -> Bytes raise SshError {
  let len = self.read_uint32().reinterpret_as_int()
  if len < 0 {
    // Length high bit set ⇒ would overflow when added to pos. Treat as
    // malformed rather than risk a panic.
    raise InvalidEncoding("string length out of range")
  }
  self.read_bytes(len)
}

///|
pub fn WireReader::read_string_ascii(
  self : WireReader,
) -> String raise SshError {
  let bytes = self.read_string()
  let buf = StringBuilder::new()
  for i = 0; i < bytes.length(); i = i + 1 {
    let c = bytes[i].to_int()
    if c < 0 || c > 0x7f {
      raise InvalidEncoding("string contains non-ASCII byte")
    }
    buf.write_char(c.to_char().unwrap())
  }
  buf.to_string()
}

///|
// Mutable buffer-backed writer that produces wire-format output.
pub struct WireWriter {
  buf : Array[Byte]
}

///|
pub fn WireWriter::new() -> WireWriter {
  { buf: [] }
}

///|
pub fn WireWriter::write_byte(self : WireWriter, b : Byte) -> Unit {
  self.buf.push(b)
}

///|
pub fn WireWriter::write_bytes_raw(self : WireWriter, bytes : Bytes) -> Unit {
  for i = 0; i < bytes.length(); i = i + 1 {
    self.buf.push(bytes[i])
  }
}

///|
pub fn WireWriter::write_uint32(self : WireWriter, v : UInt) -> Unit {
  self.buf.push((v >> 24).to_byte())
  self.buf.push(((v >> 16) & 0xffU).to_byte())
  self.buf.push(((v >> 8) & 0xffU).to_byte())
  self.buf.push((v & 0xffU).to_byte())
}

///|
pub fn WireWriter::write_string(self : WireWriter, bytes : Bytes) -> Unit {
  self.write_uint32(bytes.length().reinterpret_as_uint())
  self.write_bytes_raw(bytes)
}

///|
pub fn WireWriter::write_string_ascii(self : WireWriter, s : String) -> Unit {
  let bytes = Bytes::makei(s.length(), fn(i) {
    s.get_char(i).unwrap().to_int().to_byte()
  })
  self.write_string(bytes)
}

///|
pub fn WireWriter::to_bytes(self : WireWriter) -> Bytes {
  Bytes::makei(self.buf.length(), fn(i) { self.buf[i] })
}

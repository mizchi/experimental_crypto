///|
pub struct PemBlock {
  label : String
  data : Bytes
  headers : Array[(String, String)]
} derive(Eq, Show)

///|
pub suberror PemError {
  InvalidFormat(String)
  UnexpectedEof
  InvalidBase64
  MissingBeginMarker
  MissingEndMarker
  LabelMismatch(begin~ : String, end~ : String)
} derive(Show)

///|
pub fn decode(input : String) -> PemBlock raise PemError {
  ignore(input)
  abort("todo: PEM decode single block")
}

///|
pub fn decode_all(input : String) -> Array[PemBlock] raise PemError {
  ignore(input)
  abort("todo: PEM decode multiple blocks")
}

///|
pub fn encode(block : PemBlock) -> String {
  ignore(block)
  abort("todo: PEM encode with headers")
}

///|
pub fn encode_simple(label : String, data : Bytes) -> String {
  ignore(label)
  ignore(data)
  abort("todo: PEM encode without headers")
}

///|
pub struct Uint {
  limbs : FixedArray[UInt64]
} derive(Eq)

///|
pub impl Show for Uint with fn output(self, logger) {
  ignore(self)
  ignore(logger)
  abort("todo: hex format")
}

///|
pub suberror CryptoBigintError {
  InvalidLength
  Overflow
  NotInvertible
} derive(Show)

///|
pub fn Uint::zero(limb_count : Int) -> Uint {
  { limbs: FixedArray::make(limb_count, 0UL) }
}

///|
pub fn Uint::one(limb_count : Int) -> Uint {
  let limbs = FixedArray::make(limb_count, 0UL)
  if limb_count > 0 {
    limbs[0] = 1UL
  }
  { limbs, }
}

///|
pub fn Uint::from_be_bytes(
  bytes : Bytes,
  limb_count : Int,
) -> Uint raise CryptoBigintError {
  ignore(bytes)
  ignore(limb_count)
  abort("todo: decode big-endian bytes into limbs")
}

///|
pub fn Uint::from_le_bytes(
  bytes : Bytes,
  limb_count : Int,
) -> Uint raise CryptoBigintError {
  ignore(bytes)
  ignore(limb_count)
  abort("todo: decode little-endian bytes into limbs")
}

///|
pub fn Uint::to_be_bytes(self : Uint) -> Bytes {
  ignore(self)
  abort("todo: encode limbs as big-endian bytes")
}

///|
pub fn Uint::to_le_bytes(self : Uint) -> Bytes {
  ignore(self)
  abort("todo: encode limbs as little-endian bytes")
}

///|
pub fn Uint::bit_len(self : Uint) -> Int {
  ignore(self)
  abort("todo: highest set bit + 1")
}

///|
pub fn Uint::ct_eq(self : Uint, other : Uint) -> Bool {
  ignore(self)
  ignore(other)
  abort("todo: constant-time equality")
}

///|
pub fn Uint::ct_lt(self : Uint, other : Uint) -> Bool {
  ignore(self)
  ignore(other)
  abort("todo: constant-time less-than")
}

///|
pub fn Uint::add_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  ignore(self)
  ignore(other)
  ignore(modulus)
  abort("todo: modular addition")
}

///|
pub fn Uint::sub_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  ignore(self)
  ignore(other)
  ignore(modulus)
  abort("todo: modular subtraction")
}

///|
pub fn Uint::mul_mod(self : Uint, other : Uint, modulus : Uint) -> Uint {
  ignore(self)
  ignore(other)
  ignore(modulus)
  abort("todo: modular multiplication")
}

///|
pub fn Uint::pow_mod(self : Uint, exponent : Uint, modulus : Uint) -> Uint {
  ignore(self)
  ignore(exponent)
  ignore(modulus)
  abort("todo: modular exponentiation")
}

///|
pub fn Uint::inv_mod(
  self : Uint,
  modulus : Uint,
) -> Uint raise CryptoBigintError {
  ignore(self)
  ignore(modulus)
  abort("todo: modular inverse")
}

///|
pub struct Montgomery {
  modulus : Uint
  r2 : Uint
  inv : UInt64
}

///|
pub fn Montgomery::new(modulus : Uint) -> Montgomery {
  ignore(modulus)
  abort("todo: precompute Montgomery parameters")
}

///|
pub fn Montgomery::to_mont(self : Montgomery, x : Uint) -> Uint {
  ignore(self)
  ignore(x)
  abort("todo: convert to Montgomery form")
}

///|
pub fn Montgomery::from_mont(self : Montgomery, x : Uint) -> Uint {
  ignore(self)
  ignore(x)
  abort("todo: convert from Montgomery form")
}

///|
pub fn Montgomery::mul(self : Montgomery, a : Uint, b : Uint) -> Uint {
  ignore(self)
  ignore(a)
  ignore(b)
  abort("todo: Montgomery multiplication")
}

///|
pub fn Montgomery::pow(self : Montgomery, base : Uint, exponent : Uint) -> Uint {
  ignore(self)
  ignore(base)
  ignore(exponent)
  abort("todo: Montgomery exponentiation")
}

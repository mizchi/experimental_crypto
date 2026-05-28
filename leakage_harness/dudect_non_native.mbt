///| Non-native in-process dudect-style runner.

///|
fn dudect_pair_first_sparse(
  pair : Int,
  round : Int,
  measurements : Int,
) -> Bool {
  let x = pair * 110351 + round * 31337 + measurements * 17 + 97
  x % 3 != 0
}

///|
fn dudect_max_abs_t(
  sparse : () -> Unit,
  dense : () -> Unit,
  measurements : Int,
  rounds : Int,
) -> Double {
  if measurements < 4 || rounds < 1 {
    return -1.0
  }
  for _ in 0..<16 {
    sparse()
    dense()
  }
  let mut max_abs_t = 0.0
  for round in 0..<rounds {
    let sparse_samples : Array[Double] = []
    let dense_samples : Array[Double] = []
    for i in 0..<measurements {
      let first_sparse = dudect_pair_first_sparse(i / 2, round, measurements)
      let is_sparse = if i % 2 == 0 {
        first_sparse
      } else if first_sparse {
        false
      } else {
        true
      }
      if is_sparse {
        sparse_samples.push(measure(sparse, 1))
      } else {
        dense_samples.push(measure(dense, 1))
      }
    }
    let t = absd(welch_t(sparse_samples, dense_samples))
    if t > max_abs_t {
      max_abs_t = t
    }
  }
  max_abs_t
}

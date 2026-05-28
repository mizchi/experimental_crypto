///| Native in-process dudect-style runner.

///|
extern "C" fn ffi_dudect_max_abs_t(
  sparse : () -> Unit,
  dense : () -> Unit,
  measurements : Int,
  rounds : Int,
) -> Double = "mz_dudect_max_abs_t"

///|
fn dudect_max_abs_t(
  sparse : () -> Unit,
  dense : () -> Unit,
  measurements : Int,
  rounds : Int,
) -> Double {
  ffi_dudect_max_abs_t(sparse, dense, measurements, rounds)
}

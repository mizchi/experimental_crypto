#include <math.h>
#include <moonbit.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

typedef struct mz_moonbit_unit_closure mz_moonbit_unit_closure_t;

struct mz_moonbit_unit_closure {
  int32_t (*code)(mz_moonbit_unit_closure_t *);
};

typedef struct {
  double mean[2];
  double m2[2];
  double n[2];
} mz_ttest_ctx_t;

static volatile int32_t mz_dudect_sink = 0;

static inline void mz_call_work(mz_moonbit_unit_closure_t *work) {
  moonbit_incref(work);
  mz_dudect_sink ^= work->code(work);
}

static inline uint64_t mz_cycles(void) {
#if defined(__x86_64__) || defined(_M_X64)
  uint32_t lo = 0;
  uint32_t hi = 0;
  __asm__ __volatile__("lfence\nrdtsc\nlfence"
                       : "=a"(lo), "=d"(hi)
                       :
                       : "memory");
  return ((uint64_t)hi << 32) | lo;
#else
  struct timespec ts;
#if defined(CLOCK_MONOTONIC_RAW)
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
  clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static uint64_t mz_xorshift64(uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

static void mz_ttest_init(mz_ttest_ctx_t *ctx) {
  ctx->mean[0] = 0.0;
  ctx->mean[1] = 0.0;
  ctx->m2[0] = 0.0;
  ctx->m2[1] = 0.0;
  ctx->n[0] = 0.0;
  ctx->n[1] = 0.0;
}

static void mz_ttest_push(mz_ttest_ctx_t *ctx, double x, uint8_t clazz) {
  ctx->n[clazz] += 1.0;
  double delta = x - ctx->mean[clazz];
  ctx->mean[clazz] += delta / ctx->n[clazz];
  ctx->m2[clazz] += delta * (x - ctx->mean[clazz]);
}

static double mz_ttest_compute(mz_ttest_ctx_t *ctx) {
  if (ctx->n[0] < 2.0 || ctx->n[1] < 2.0) {
    return 0.0;
  }
  double var0 = ctx->m2[0] / (ctx->n[0] - 1.0);
  double var1 = ctx->m2[1] / (ctx->n[1] - 1.0);
  double den = sqrt(var0 / ctx->n[0] + var1 / ctx->n[1]);
  if (den <= 0.0) {
    return 0.0;
  }
  return (ctx->mean[0] - ctx->mean[1]) / den;
}

double mz_dudect_max_abs_t(
  mz_moonbit_unit_closure_t *sparse,
  mz_moonbit_unit_closure_t *dense,
  int32_t measurements,
  int32_t rounds
) {
  if (measurements < 4 || rounds < 1) {
    return -1.0;
  }

  for (int32_t i = 0; i < 16; i++) {
    mz_call_work(sparse);
    mz_call_work(dense);
  }

  uint64_t rng = 0x9e3779b97f4a7c15ULL ^
                 ((uint64_t)(uint32_t)measurements << 32) ^
                 (uint64_t)(uint32_t)rounds;
  double max_abs_t = 0.0;

  for (int32_t round = 0; round < rounds; round++) {
    mz_ttest_ctx_t ctx;
    mz_ttest_init(&ctx);

    for (int32_t i = 0; i < measurements; i++) {
      uint8_t clazz = (uint8_t)(mz_xorshift64(&rng) & 1U);
      uint64_t start = mz_cycles();
      if (clazz == 0) {
        mz_call_work(sparse);
      } else {
        mz_call_work(dense);
      }
      uint64_t end = mz_cycles();
      if (end >= start) {
        mz_ttest_push(&ctx, (double)(end - start), clazz);
      }
    }

    double t = fabs(mz_ttest_compute(&ctx));
    if (t > max_abs_t) {
      max_abs_t = t;
    }
  }

  return max_abs_t;
}

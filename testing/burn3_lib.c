/* Shared-library half of burn3. Built as libburn3.so.
 *
 * Exists so the profiler has to resolve symbols in a shared object that is
 * NOT glibc, and so some stacks cross executable -> libburn3.so -> libm.so.
 *
 * Build (see burn3.c for the full recipe):
 *     gcc -O0 -fno-inline -fno-omit-frame-pointer -g -fPIC -shared \
 *         -o libburn3.so burn3_lib.c -lm
 */

#include <math.h>
#include <stddef.h>
#include <stdint.h>

__attribute__((noinline))
uint64_t lib_round(uint64_t h, uint64_t v) {
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h * 0xff51afd7ed558ccdULL;
}

/* Hot path: lib_checksum -> lib_round */
__attribute__((noinline))
uint64_t lib_checksum(const unsigned char *buf, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h = lib_round(h, buf[i]);
    }
    return h;
}

/* A static (local-symbol) function inside the library, calling into libm. */
__attribute__((noinline))
static double lib_cell(double x) {
    return sin(x) * cos(x) + sqrt(fabs(x));
}

/* Hot path: lib_transform -> lib_cell -> sin/cos/sqrt (libm.so) */
__attribute__((noinline))
void lib_transform(double *m, size_t n) {
    for (size_t i = 0; i < n; i++) {
        m[i] = lib_cell(m[i] + (double)i);
    }
}

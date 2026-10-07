/* A more complex CPU-burning test program for exercising hamlet.
 *
 * Compared to burn.c (a single main -> foo -> bar chain), this has several
 * different call paths with different weights, so a flamegraph should show a
 * tree with boxes of clearly different widths:
 *
 *   main
 *   |- run_primes   -> count_primes -> is_prime            (heavy, pure compute)
 *   |- run_sort     -> fill_random -> next_rand            (calls into libc's qsort,
 *   |                 qsort -> compare_ints                 which calls back into us)
 *   |- run_fib      -> fib -> fib -> fib ...               (deep recursion)
 *   |- run_syscalls -> do_write / do_getpid                (kernel frames: [k] write, ...)
 *   `- run_math     -> sin/cos/sqrt                        (libm shared-library frames)
 *   worker thread:
 *   `- background_hash -> hash_buffer -> mix                (second thread, same pid)
 *
 * Rough expected weight (main thread), so you know what "right" looks like:
 *   primes ~40%, sort ~20%, fib ~20%, syscalls ~10%, math ~10%
 * The worker thread burns a second core on its own.
 *
 * noinline + -O0 keep every function a real, separate symbol.
 *
 * Build (keep the symbol table - do NOT strip):
 *     gcc -O0 -fno-inline -g -pthread -o burn2 burn2.c -lm
 *
 * Run:
 *     ./burn2 &
 *     sudo -E ./target/release/hamlet --pid $! > out.folded
 */

#include <fcntl.h>
#include <math.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

/* Volatile sink so nothing gets optimised away, even if built with -O2. */
static volatile uint64_t sink;

/* ---------- primes: pure compute, deepest hot path ---------- */

__attribute__((noinline))
static int is_prime(long n) {
    if (n < 2) return 0;
    for (long d = 2; d * d <= n; d++) {
        if (n % d == 0) return 0;
    }
    return 1;
}

__attribute__((noinline))
static long count_primes(long limit) {
    long count = 0;
    for (long n = 2; n < limit; n++) {
        count += is_prime(n);
    }
    return count;
}

__attribute__((noinline))
static void run_primes(void) {
    sink += count_primes(40000);
}

/* ---------- sort: libc's qsort calling back into our comparator ---------- */

static uint64_t rng_state = 88172645463325252ULL;

__attribute__((noinline))
static uint64_t next_rand(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

__attribute__((noinline))
static void fill_random(int *a, int n) {
    for (int i = 0; i < n; i++) {
        a[i] = (int)(next_rand() % 100000);
    }
}

__attribute__((noinline))
static int compare_ints(const void *x, const void *y) {
    int a = *(const int *)x, b = *(const int *)y;
    return (a > b) - (a < b);
}

__attribute__((noinline))
static void run_sort(void) {
    enum { N = 20000 };
    static int data[N];
    fill_random(data, N);
    qsort(data, N, sizeof(int), compare_ints);
    sink += data[N / 2];
}

/* ---------- fib: deep, branching recursion ---------- */

__attribute__((noinline))
static long fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

__attribute__((noinline))
static void run_fib(void) {
    sink += fib(27);
}

/* ---------- syscalls: should produce kernel-side frames ---------- */

__attribute__((noinline))
static void do_write(int fd) {
    char buf[256] = {0};
    if (write(fd, buf, sizeof(buf)) < 0) sink++;
}

__attribute__((noinline))
static void do_getpid(void) {
    sink += (uint64_t)getpid();
}

__attribute__((noinline))
static void run_syscalls(void) {
    int fd = open("/dev/null", O_WRONLY);
    for (int i = 0; i < 20000; i++) {
        do_write(fd);
        do_getpid();
    }
    close(fd);
}

/* ---------- math: frames inside libm.so ---------- */

__attribute__((noinline))
static void run_math(void) {
    double acc = 0;
    for (int i = 1; i < 200000; i++) {
        acc += sin((double)i) * cos((double)i) + sqrt((double)i);
    }
    sink += (uint64_t)acc;
}

/* ---------- worker thread: same pid, different stack ---------- */

__attribute__((noinline))
static uint64_t mix(uint64_t h, uint64_t v) {
    h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
    return h * 0xff51afd7ed558ccdULL;
}

__attribute__((noinline))
static uint64_t hash_buffer(const unsigned char *buf, int len) {
    uint64_t h = 1469598103934665603ULL;
    for (int i = 0; i < len; i++) {
        h = mix(h, buf[i]);
    }
    return h;
}

static void *background_hash(void *arg) {
    (void)arg;
    unsigned char buf[4096];
    for (int i = 0; i < 4096; i++) buf[i] = (unsigned char)i;
    for (;;) {
        sink += hash_buffer(buf, sizeof(buf));
    }
    return NULL;
}

/* ---------- main ---------- */

int main(void) {
    pthread_t t;
    pthread_create(&t, NULL, background_hash, NULL);

    for (;;) {
        run_primes();
        run_sort();
        run_fib();
        run_syscalls();
        run_math();
    }
    return 0;
}

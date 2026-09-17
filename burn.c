/* Small CPU-burning test program for exercising hamlet's userspace symbol
 * resolution. Runs a chain of nested function calls in a tight infinite
 * loop, so sampled stack traces show distinct frames: main -> foo -> bar.
 *
 * noinline + no optimization keep each function as a real, separate
 * symbol in the binary instead of being inlined away.
 *
 * Build (keep the symbol table - do NOT strip):
 *     gcc -O0 -fno-inline -o burn burn.c
 *
 * Run:
 *     ./burn &
 *     cargo run --release -- --pid $!
 */

__attribute__((noinline))
long bar(long x) {
    long total = 0;
    for (long i = 0; i < 1000; i++) {
        total += (x * i) % 7919;
    }
    return total;
}

__attribute__((noinline))
long foo(long x) {
    return bar(x) + bar(x + 1);
}

int main(void) {
    long x = 0;
    for (;;) {
        x = foo(x) % 1000;
    }
    return 0;
}

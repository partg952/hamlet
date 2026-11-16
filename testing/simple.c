/* The simplest possible program for learning how a CPU profiler works.
 *
 * Every function that burns CPU ends up calling the same helper, spin(), and
 * one unit of spin() is always the same amount of work. The only thing that
 * differs between the three tasks is HOW MANY units they ask for:
 *
 *     slow_task   -> spin(6)      6 units
 *     medium_task -> spin(3)      3 units
 *     fast_task   -> spin(1)      1 unit
 *
 * So out of the 10 units per pass, the CPU time should split about
 *
 *     slow 60%   medium 30%   fast 10%
 *
 * and that is what the flame graph should show. Same helper (spin), three
 * different callers, three different widths. That's the whole idea:
 *
 *   - the stack (rows, bottom to top) shows WHO CALLED WHOM
 *   - the width of a box shows how much of the CPU time was spent in it
 *
 * Expected call tree (bottom = root):
 *
 *   simple
 *   `- _start -> __libc_start_main -> main
 *      `- do_work
 *         |- slow_task   -> spin     (~60%)
 *         |- medium_task -> spin     (~30%)
 *         `- fast_task   -> spin     (~10%)
 *
 * One more lesson: rest() sleeps. A CPU profiler only samples code that is
 * running on a CPU, so the sleeping time does NOT appear in the graph at all,
 * even though it takes about as much wall-clock time as the real work.
 * (Samples are only counted while the program is on a CPU.)
 *
 * -O0 / -fno-inline / frame pointers keep every function a real, separate
 * frame so the stacks are complete. Do NOT strip the binary.
 *
 * Build:
 *     gcc -O0 -fno-inline -fno-omit-frame-pointer -g -no-pie -o simple simple.c
 *
 * Run from this directory (testing/). The optional argument is how many
 * seconds to run; default 15:
 *     ./simple 15 &
 *     sudo ../target/release/hamlet --pid $! --duration 10 --flamegraph output/flame_simple.svg
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* volatile: stops the compiler from deleting the "useless" loop below. */
static volatile uint64_t sink;

/* One unit of work = one million additions. Everything funnels through here. */
__attribute__((noinline))
static void spin(long units) {
    for (long u = 0; u < units; u++) {
        for (long i = 0; i < 1000000; i++) {
            sink += i;
        }
    }
}

__attribute__((noinline)) static void slow_task(void)   { spin(6); }
__attribute__((noinline)) static void medium_task(void) { spin(3); }
__attribute__((noinline)) static void fast_task(void)   { spin(1); }

__attribute__((noinline))
static void do_work(void) {
    slow_task();
    medium_task();
    fast_task();
}

/* Waiting, not working: the program is asleep, so the profiler sees nothing. */
__attribute__((noinline))
static void rest(void) {
    usleep(20000); /* 20 ms */
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char **argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 15;
    fprintf(stderr, "simple: pid %d, running for %d seconds\n", (int)getpid(), seconds);

    double deadline = now_sec() + seconds;
    while (now_sec() < deadline) {
        do_work();
        rest();
    }
    return 0;
}

/* A harder CPU-burning test program for exercising hamlet.
 *
 * burn2 covers hot loops, libc's qsort and plain syscalls. burn3 targets the
 * things DESIGN.md lists as unverified or untested:
 *
 *   - symbols in a shared library that is not glibc     (libburn3.so)
 *   - stacks that cross exe -> libburn3.so -> libm.so   (run_lib_math)
 *   - the vDSO, which has no file on disk               (run_time_calls)
 *   - a signal handler running on top of user code      (on_alarm, SIGALRM)
 *   - recursion deeper than the 127-frame stack limit   (run_deep)
 *   - threads blocking on a mutex/condvar               (producer/consumer)
 *   - page faults and mmap/munmap from big allocations  (alloc_churn)
 *   - indirect calls through a function-pointer table   (run_dispatch)
 *   - libc string functions                             (run_strings)
 *
 * Call tree (what a correct flamegraph should contain):
 *
 *   main thread
 *   |- run_matmul   -> matmul -> cell_dot
 *   |- run_strings  -> format_item (snprintf) / find_marker (strstr) / strtol
 *   |- run_dispatch -> run_ops -> op_add / op_xor / op_rot / op_mul
 *   |- run_deep     -> deep_recurse x300 -> burn_leaf -> next_rand
 *   |- run_lib_math -> lib_transform -> lib_cell -> sin/cos/sqrt (libm)
 *   |- run_time_calls    -> clock_gettime (vDSO, user space)
 *   |- run_raw_syscalls  -> syscall -> kernel frames
 *   `- on_alarm (SIGALRM every 10ms) -> signal_work   (via __restore_rt)
 *   thread "producer":    producer_thread -> fill_buffer -> next_rand,
 *                         queue_push (mutex/condvar, often asleep)
 *   thread "consumer":    consumer_thread -> lib_checksum -> lib_round
 *   thread "alloc-churn": alloc_churn_thread -> churn_round -> malloc/memset
 *
 * I have not measured the weights, so use the profiler to find out. Roughly:
 * the consumer and the main thread should dominate; the producer is mostly
 * blocked once the queue is full.
 *
 * noinline + -O0 + frame pointers keep every function a real, separate frame.
 *
 * Build (keep the symbol table - do NOT strip). Run from this directory (testing/):
 *
 *   gcc -O0 -fno-inline -fno-omit-frame-pointer -g -fPIC -shared \
 *       -o libburn3.so burn3_lib.c -lm
 *
 *   non-PIE executable:
 *   gcc -O0 -fno-inline -fno-omit-frame-pointer -g -no-pie -pthread \
 *       -o burn3_nopie burn3.c -L. -lburn3 -Wl,-rpath,'$ORIGIN' -lm
 *
 *   PIE executable:
 *   gcc -O0 -fno-inline -fno-omit-frame-pointer -g -pie -fPIE -pthread \
 *       -o burn3_pie burn3.c -L. -lburn3 -Wl,-rpath,'$ORIGIN' -lm
 *
 * Run (an optional argument stops the program after that many seconds;
 * with no argument it runs until killed):
 *
 *   ./burn3_nopie &
 *   sudo ../target/release/hamlet --pid $! --duration 10 --flamegraph output/flame_burn3_nopie.svg
 *   kill $!
 */

#define _GNU_SOURCE
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NOINLINE __attribute__((noinline))

/* Provided by libburn3.so. */
uint64_t lib_checksum(const unsigned char *buf, size_t len);
void lib_transform(double *m, size_t n);

/* Sink so nothing is optimised away, even at -O2. Atomic: many threads. */
static uint64_t sink;
#define SINK(x) __atomic_fetch_add(&sink, (uint64_t)(x), __ATOMIC_RELAXED)

static volatile sig_atomic_t stop;

/* Per-thread xorshift, so threads don't race on shared RNG state. */
static __thread uint64_t rng_state = 88172645463325252ULL;

NOINLINE
static uint64_t next_rand(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return rng_state;
}

static double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* ---------- matmul: nested loops with a helper call per cell ---------- */

#define N 96
static double A[N][N], B[N][N], C[N][N];

NOINLINE
static double cell_dot(int i, int j) {
    double s = 0;
    for (int k = 0; k < N; k++) s += A[i][k] * B[k][j];
    return s;
}

NOINLINE
static void matmul(void) {
    for (int i = 0; i < N; i++)
        for (int j = 0; j < N; j++)
            C[i][j] = cell_dot(i, j);
}

NOINLINE
static void run_matmul(void) {
    static int initialised;
    if (!initialised) {
        for (int i = 0; i < N; i++)
            for (int j = 0; j < N; j++) {
                A[i][j] = (double)(next_rand() % 100) / 10.0;
                B[i][j] = (double)(next_rand() % 100) / 10.0;
            }
        initialised = 1;
    }
    matmul();
    SINK((uint64_t)C[N / 2][N / 2]);
}

/* ---------- strings: libc snprintf / strstr / strlen / strtol ---------- */

NOINLINE
static size_t format_item(char *buf, size_t cap, int i) {
    return (size_t)snprintf(buf, cap, "item-%d-%s-%08x", i, "alpha",
                            (unsigned)i * 2654435761u);
}

NOINLINE
static int find_marker(const char *s) {
    return strstr(s, "-alpha-") != NULL;
}

NOINLINE
static void run_strings(void) {
    char buf[64];
    uint64_t total = 0;
    for (int i = 0; i < 30000; i++) {
        format_item(buf, sizeof(buf), i);
        total += (uint64_t)find_marker(buf);
        total += strlen(buf);
        total += (uint64_t)strtol(buf + 5, NULL, 10);
    }
    SINK(total);
}

/* ---------- dispatch: indirect calls through a function-pointer table ---------- */

typedef uint64_t (*op_fn)(uint64_t, uint64_t);

NOINLINE static uint64_t op_add(uint64_t a, uint64_t b) { return a + b; }
NOINLINE static uint64_t op_xor(uint64_t a, uint64_t b) { return a ^ (b << 3); }
NOINLINE static uint64_t op_rot(uint64_t a, uint64_t b) { return ((a << 7) | (a >> 57)) ^ b; }
NOINLINE static uint64_t op_mul(uint64_t a, uint64_t b) { return a * (b | 1); }

/* Skewed on purpose: add 4/8, xor 2/8, rot 1/8, mul 1/8. */
static const op_fn ops[8] = {op_add, op_add, op_add, op_add,
                             op_xor, op_xor, op_rot, op_mul};

NOINLINE
static uint64_t run_ops(uint64_t n) {
    uint64_t acc = 1;
    for (uint64_t i = 0; i < n; i++) acc = ops[i & 7](acc, i);
    return acc;
}

NOINLINE
static void run_dispatch(void) {
    SINK(run_ops(3000000));
}

/* ---------- deep recursion: ~300 frames, past the 127-frame stack limit ---------- */

NOINLINE
static uint64_t burn_leaf(void) {
    uint64_t a = 0;
    for (int i = 0; i < 2000; i++) a += next_rand() & 7;
    return a;
}

NOINLINE
static uint64_t deep_recurse(int depth) {
    if (depth == 0) return burn_leaf();
    return deep_recurse(depth - 1) + 1;
}

NOINLINE
static void run_deep(void) {
    for (int rep = 0; rep < 1500; rep++) SINK(deep_recurse(300));
}

/* ---------- libburn3.so -> libm.so: a stack crossing two libraries ---------- */

static double lib_buf[4096];

NOINLINE
static void run_lib_math(void) {
    for (int i = 0; i < 4096; i++) lib_buf[i] = (double)i * 0.001;
    for (int r = 0; r < 20; r++) lib_transform(lib_buf, 4096);
    SINK((uint64_t)fabs(lib_buf[10]));
}

/* ---------- vDSO + real syscalls ---------- */

/* clock_gettime is serviced from the [vdso] mapping, in user space. */
NOINLINE
static void run_time_calls(void) {
    struct timespec ts;
    for (int i = 0; i < 500000; i++) {
        clock_gettime(CLOCK_MONOTONIC, &ts);
        SINK(ts.tv_nsec);
    }
}

/* syscall() forces a real kernel entry, so samples carry kernel frames. */
NOINLINE
static void run_raw_syscalls(void) {
    for (int i = 0; i < 100000; i++) SINK(syscall(SYS_getppid));
}

/* ---------- signal handler: SIGALRM every 10ms runs on top of user code ---------- */

NOINLINE
static void signal_work(void) {
    volatile uint64_t a = 0;
    for (int i = 0; i < 200000; i++) a += (uint64_t)i * (uint64_t)i;
    SINK(a);
}

static void on_alarm(int sig) {
    (void)sig;
    signal_work();
}

/* ---------- producer / consumer: mutex + condvar, threads that block ---------- */

#define QCAP 8
#define BUFSZ 8192

static unsigned char *queue[QCAP];
static int q_head, q_tail, q_count;
static pthread_mutex_t q_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t q_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t q_not_full = PTHREAD_COND_INITIALIZER;

/* Returns 1 on success, 0 if the program is shutting down. */
NOINLINE
static int queue_push(unsigned char *b) {
    pthread_mutex_lock(&q_lock);
    while (q_count == QCAP && !stop) pthread_cond_wait(&q_not_full, &q_lock);
    if (stop) {
        pthread_mutex_unlock(&q_lock);
        return 0;
    }
    queue[q_tail] = b;
    q_tail = (q_tail + 1) % QCAP;
    q_count++;
    pthread_cond_signal(&q_not_empty);
    pthread_mutex_unlock(&q_lock);
    return 1;
}

/* Returns NULL if the program is shutting down. */
NOINLINE
static unsigned char *queue_pop(void) {
    pthread_mutex_lock(&q_lock);
    while (q_count == 0 && !stop) pthread_cond_wait(&q_not_empty, &q_lock);
    if (q_count == 0) {
        pthread_mutex_unlock(&q_lock);
        return NULL;
    }
    unsigned char *b = queue[q_head];
    q_head = (q_head + 1) % QCAP;
    q_count--;
    pthread_cond_signal(&q_not_full);
    pthread_mutex_unlock(&q_lock);
    return b;
}

NOINLINE
static void fill_buffer(unsigned char *b) {
    for (int i = 0; i < BUFSZ; i++) b[i] = (unsigned char)(next_rand() & 0xff);
}

static void *producer_thread(void *arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "producer");
    while (!stop) {
        unsigned char *b = malloc(BUFSZ);
        if (!b) break;
        fill_buffer(b);
        if (!queue_push(b)) {
            free(b);
            break;
        }
    }
    return NULL;
}

static void *consumer_thread(void *arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "consumer");
    while (!stop) {
        unsigned char *b = queue_pop();
        if (!b) break;
        SINK(lib_checksum(b, BUFSZ));
        free(b);
    }
    return NULL;
}

/* ---------- allocator churn: big mallocs -> mmap/munmap and page faults ---------- */

NOINLINE
static void touch_memory(void *p, size_t n) {
    memset(p, 0xAB, n);
}

NOINLINE
static void churn_round(void **slots, int count) {
    for (int i = 0; i < count; i++) {
        free(slots[i]);
        size_t sz = 64 + (size_t)(next_rand() % 300000);
        slots[i] = malloc(sz);
        if (slots[i]) touch_memory(slots[i], sz);
    }
}

static void *alloc_churn_thread(void *arg) {
    (void)arg;
    pthread_setname_np(pthread_self(), "alloc-churn");
    void *slots[64] = {0};
    while (!stop) churn_round(slots, 64);
    for (int i = 0; i < 64; i++) free(slots[i]);
    return NULL;
}

/* ---------- main ---------- */

int main(int argc, char **argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 0;
    fprintf(stderr, "burn3 pid %d, %s\n", (int)getpid(),
            seconds > 0 ? "will stop by itself" : "runs until killed");

    /* Block SIGALRM before creating threads (they inherit the mask), so only
     * the main thread ever runs the handler. */
    sigset_t alarm_set;
    sigemptyset(&alarm_set);
    sigaddset(&alarm_set, SIGALRM);
    pthread_sigmask(SIG_BLOCK, &alarm_set, NULL);

    pthread_t producer, consumer, churn;
    pthread_create(&producer, NULL, producer_thread, NULL);
    pthread_create(&consumer, NULL, consumer_thread, NULL);
    pthread_create(&churn, NULL, alloc_churn_thread, NULL);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sa.sa_flags = SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    pthread_sigmask(SIG_UNBLOCK, &alarm_set, NULL);

    struct itimerval it = {{0, 10000}, {0, 10000}};
    setitimer(ITIMER_REAL, &it, NULL);

    double deadline = seconds > 0 ? now_sec() + seconds : 0;
    while (!stop) {
        run_matmul();
        run_strings();
        run_dispatch();
        run_deep();
        run_lib_math();
        run_time_calls();
        run_raw_syscalls();
        if (deadline > 0 && now_sec() >= deadline) stop = 1;
    }

    /* Wake any thread blocked on the queue so it can see `stop`. */
    pthread_mutex_lock(&q_lock);
    pthread_cond_broadcast(&q_not_empty);
    pthread_cond_broadcast(&q_not_full);
    pthread_mutex_unlock(&q_lock);

    pthread_join(producer, NULL);
    pthread_join(consumer, NULL);
    pthread_join(churn, NULL);
    return 0;
}

/* Freestanding env-dump workload for the boatramp microVM env-drop validation.
 *
 * vminit (PID 1) mounts devtmpfs at /dev, then execve()s this as the workload.
 * It walks its own stack to find envp (x86_64 SysV: rsp -> argc, argv[], NULL,
 * envp[], NULL), opens /dev/console directly (robust even if the kernel didn't
 * wire fds 0/1/2 to a console), writes every KEY=VALUE it received bracketed by
 * sentinels, then blocks forever (exiting as PID 1 panics the kernel and would
 * truncate the serial mid-flush). If the launch-time env channel
 * (boatramp.env=<hex> on the kernel cmdline, decoded by vminit) works, the
 * runtime vars appear here.
 *
 *   cc -static -nostdlib -ffreestanding -no-pie -Os -o envdump envdump.c
 */
#define SYS_write 1
#define SYS_open 2
#define SYS_pause 34
#define SYS_exit 60
#define O_WRONLY 1

static long sys3(long n, long a, long b, long c) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(n), "D"(a), "S"(b), "d"(c)
                     : "rcx", "r11", "memory");
    return r;
}
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

static long g_fd = 1;
static void w(const char *s) { sys3(SYS_write, g_fd, (long)s, slen(s)); }

void cmain(long argc, char **argv) {
    char **envp = argv + argc + 1;
    long fd = sys3(SYS_open, (long)"/dev/console", O_WRONLY, 0);
    if (fd >= 0) g_fd = fd; /* else keep the inherited fd 1 */
    w("BR_ENVDUMP_BEGIN\n");
    for (char **e = envp; *e; e++) { w(*e); w("\n"); }
    w("BR_ENVDUMP_END\n");
    /* Do NOT exit: as PID 1, exiting panics the kernel ("Attempted to kill
     * init") and truncates the serial mid-flush. Block forever so the full dump
     * drains and the harness observes it. */
    for (;;) sys3(SYS_pause, 0, 0, 0);
}

__asm__(
    ".global _start\n"
    "_start:\n"
    "  xor %rbp, %rbp\n"
    "  mov (%rsp), %rdi\n"   /* argc */
    "  lea 8(%rsp), %rsi\n"  /* argv */
    "  and $-16, %rsp\n"
    "  call cmain\n"
    "  hlt\n");

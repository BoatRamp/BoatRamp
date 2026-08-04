/* boatramp microVM guest init.
 *
 * A tiny **freestanding** PID-1: mount the kernel pseudo-filesystems, read the
 * baked exec spec (/etc/boatramp/{argv,env,cwd}), and `execve` the workload. No
 * libc (raw x86_64 syscalls + a custom `_start`), so the single static binary
 * runs as /sbin/init in *any* rootfs — busybox/alpine/debian *and* shell-less
 * scratch/distroless images. Built with:
 *   cc -static -nostdlib -ffreestanding -no-pie -Os
 *
 * `boatramp_firecracker::oci::build_rootfs` writes this to /sbin/init, creates
 * the mount-point dirs (the root is mounted read-only, so they must pre-exist),
 * and writes the NUL-separated argv/env + cwd files this reads.
 */

/* x86_64 syscall numbers. */
#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_execve 59
#define SYS_exit 60
#define SYS_chdir 80
#define SYS_mkdir 83
#define SYS_mount 165

#define O_RDONLY 0

static long sys(long n, long a, long b, long c, long d, long e) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall"
                     : "=a"(r)
                     : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return r;
}

static int slen(const char *s) {
    int n = 0;
    while (s[n]) n++;
    return n;
}

static void emit(const char *s) { sys(SYS_write, 2, (long)s, slen(s), 0, 0); }

static void die(const char *msg) {
    emit(msg);
    sys(SYS_exit, 1, 0, 0, 0, 0);
}

/* Read up to `cap` bytes of `path` into `buf`; returns the byte count (or -1). */
static int read_file(const char *path, char *buf, int cap) {
    long fd = sys(SYS_open, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return -1;
    int total = 0;
    while (total < cap) {
        long n = sys(SYS_read, fd, (long)(buf + total), cap - total, 0, 0);
        if (n <= 0) break;
        total += (int)n;
    }
    sys(SYS_close, fd, 0, 0, 0, 0);
    return total;
}

/* Point `out[]` (NULL-terminated) at each NUL-separated string in buf[0..len). */
static void split_nul(char *buf, int len, char **out, int maxn) {
    int n = 0, i = 0;
    while (i < len && n < maxn - 1) {
        out[n++] = &buf[i];
        while (i < len && buf[i]) i++;
        i++; /* skip the NUL terminator */
    }
    out[n] = 0;
}

/* Find `needle` in buf[0..len); returns a pointer into buf, or 0. */
static char *find_sub(char *buf, int len, const char *needle) {
    int nl = slen(needle);
    for (int i = 0; i + nl <= len; i++) {
        int j = 0;
        while (j < nl && buf[i + j] == needle[j]) j++;
        if (j == nl) return &buf[i];
    }
    return 0;
}

/* Hex nibble value, or -1 for a non-hex char (which ends the run). */
static int hexv(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex from p (until a non-hex byte or `end`) into out[0..cap); returns bytes. */
static int hexdec(char *p, char *end, char *out, int cap) {
    int n = 0;
    while (p + 1 < end && n < cap) {
        int hi = hexv(p[0]), lo = hexv(p[1]);
        if (hi < 0 || lo < 0) break;
        out[n++] = (char)((hi << 4) | lo);
        p += 2;
    }
    return n;
}

static void mount_fs(const char *src, const char *target, const char *fstype) {
    sys(SYS_mkdir, (long)target, 0755, 0, 0, 0);            /* no-op if it exists */
    sys(SYS_mount, (long)src, (long)target, (long)fstype, 0, 0); /* best-effort */
}

/* .bss (zeroed by the kernel at load); kept off the stack. */
static char argv_buf[8192];
static char env_buf[8192];
static char cwd_buf[1024];
static char mounts_buf[2048];
static char cmdline_buf[16384];
static char renv_buf[8192];
static char *argv[256];
static char *envp[256];
static char *mounts[128];

void _start(void) {
    mount_fs("proc", "/proc", "proc");
    mount_fs("sysfs", "/sys", "sysfs");
    mount_fs("devtmpfs", "/dev", "devtmpfs");
    mount_fs("tmpfs", "/tmp", "tmpfs");
    mount_fs("tmpfs", "/run", "tmpfs");

    /* Persistent volumes: /etc/boatramp/mounts is NUL-separated
     * source\0target\0source\0target… — each an ext4 image (/dev/vdb, …)
     * mounted at a baked-in dir. devtmpfs above makes the device nodes exist;
     * best-effort (a missing file or failed mount must not block the workload). */
    int mn = read_file("/etc/boatramp/mounts", mounts_buf, sizeof mounts_buf);
    if (mn > 0) {
        split_nul(mounts_buf, mn, mounts, 128);
        for (int i = 0; mounts[i] && mounts[i + 1]; i += 2)
            sys(SYS_mount, (long)mounts[i], (long)mounts[i + 1], (long)"ext4", 0, 0);
    }

    int al = read_file("/etc/boatramp/argv", argv_buf, sizeof argv_buf);
    if (al <= 0) die("vminit: missing /etc/boatramp/argv\n");
    split_nul(argv_buf, al, argv, 256);

    /* Runtime env from the kernel cmdline (boatramp.env=<hex NUL-joined K=V>) — the
     * launch-time channel, since the baked /etc/boatramp/env is on the read-only
     * rootfs. Runtime entries go FIRST in envp, so they override the baked env. */
    int rn = 0;
    int cml = read_file("/proc/cmdline", cmdline_buf, sizeof cmdline_buf);
    if (cml > 0) {
        char *p = find_sub(cmdline_buf, cml, "boatramp.env=");
        if (p) {
            p += slen("boatramp.env=");
            int rl = hexdec(p, cmdline_buf + cml, renv_buf, sizeof renv_buf);
            int i = 0;
            while (i < rl && rn < 255) {
                envp[rn++] = &renv_buf[i];
                while (i < rl && renv_buf[i]) i++;
                i++; /* skip the NUL terminator */
            }
        }
    }
    /* Baked image env, appended after the runtime entries. */
    int el = read_file("/etc/boatramp/env", env_buf, sizeof env_buf);
    if (el < 0) el = 0;
    {
        int n = rn, i = 0;
        while (i < el && n < 255) {
            envp[n++] = &env_buf[i];
            while (i < el && env_buf[i]) i++;
            i++;
        }
        envp[n] = 0;
    }

    int cl = read_file("/etc/boatramp/cwd", cwd_buf, sizeof cwd_buf - 1);
    if (cl > 0) {
        if (cwd_buf[cl - 1] == '\n') cl--;
        cwd_buf[cl] = 0;
        sys(SYS_chdir, (long)cwd_buf, 0, 0, 0, 0); /* best-effort */
    }

    sys(SYS_execve, (long)argv[0], (long)argv, (long)envp, 0, 0);
    die("vminit: execve failed\n");
}

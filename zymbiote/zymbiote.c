/*
 * zymbiote.c — rustFrida Zymbiote 载荷
 *
 * 注入到 Zygote 进程，hook setArgV0 和 selinux_android_setcontext。
 * 当新 App 从 Zygote fork 出来时，zymbiote 触发并暂停子进程，
 * 等待 rustFrida 注入 agent 后再恢复。
 *
 * 基于 Frida 的 frida-core/src/linux/helpers/zymbiote.c 改写。
 */

#include <errno.h>
#include <jni.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ========== ZymbioteContext ========== */
/* 此结构体的布局必须与 Rust 侧（spawn.rs）写入顺序完全一致 */
typedef struct _ZymbioteContext ZymbioteContext;

struct _ZymbioteContext
{
    char socket_path[64];           /* 0:   abstract Unix socket 路径 */

    void *payload_base;             /* 64:  payload 写入的基地址 */
    size_t payload_size;            /* 72:  payload 大小 */
    size_t payload_original_protection; /* 80: 原始页保护位 */

    char *package_name;             /* 88:  NULL（由 setcontext hook 运行时填充）*/

    int     (*original_setcontext)(uid_t uid, bool is_system_server, const char *seinfo, const char *name);
    void    (*original_set_argv0)(JNIEnv *env, jobject clazz, jstring name);

    /* 12 个 libc 函数指针 */
    int     (*mprotect)(void *addr, size_t len, int prot);
    char *  (*strdup)(const char *s);
    void    (*free)(void *ptr);
    int     (*socket)(int domain, int type, int protocol);
    int     (*connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    int *   (*__errno)(void);
    pid_t   (*getpid)(void);
    pid_t   (*getppid)(void);
    ssize_t (*sendmsg)(int sockfd, const struct msghdr *msg, int flags);
    ssize_t (*recv)(int sockfd, void *buf, size_t len, int flags);
    int     (*close)(int fd);
    int     (*raise)(int sig);
};

/* 全局上下文实例（运行时由 Rust 侧通过 /proc/pid/mem 填充） */
ZymbioteContext zymbiote =
{
    .socket_path = "/rustfrida-zymbiote-00000000000000000000000000000000",
};

/* 前向声明 */
int rustfrida_zymbiote_replacement_setargv0(JNIEnv *env, jobject clazz, jstring name);
int rustfrida_zymbiote_replacement_setcontext(uid_t uid, bool is_system_server, const char *seinfo, const char *name);

static void rustfrida_wait_for_permission_to_resume(const char *package_name, bool *revert_now);
static int rustfrida_stop_and_return_from_setargv0(JNIEnv *env, jobject clazz, jstring name);
static int rustfrida_get_errno(void);
static int rustfrida_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
static ssize_t rustfrida_sendmsg(int sockfd, const struct msghdr *msg, int flags);
static bool rustfrida_sendmsg_all(int sockfd, struct iovec *iov, size_t iovlen, int flags);
static ssize_t rustfrida_recv(int sockfd, void *buf, size_t len, int flags);

/* ========== setcontext 替换函数 ========== */
__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_setcontext(uid_t uid, bool is_system_server, const char *seinfo, const char *name)
{
    int res;

    res = zymbiote.original_setcontext(uid, is_system_server, seinfo, name);
    if (res == -1)
        return -1;

    if (zymbiote.package_name == NULL)
    {
        zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                          PROT_READ | PROT_WRITE | PROT_EXEC);
        zymbiote.package_name = zymbiote.strdup(name);
    }

    return res;
}

/* ========== setArgV0 替换函数 ========== */
__attribute__((section(".text.entrypoint")))
__attribute__((visibility("default")))
int
rustfrida_zymbiote_replacement_setargv0(JNIEnv *env, jobject clazz, jstring name)
{
    const char *name_utf8;
    bool revert_now;

    zymbiote.original_set_argv0(env, clazz, name);

    if (zymbiote.package_name != NULL)
        name_utf8 = zymbiote.package_name;
    else
        name_utf8 = (*env)->GetStringUTFChars(env, name, NULL);

    rustfrida_wait_for_permission_to_resume(name_utf8, &revert_now);

    if (zymbiote.package_name != NULL)
    {
        zymbiote.free(zymbiote.package_name);
        zymbiote.package_name = NULL;
        zymbiote.mprotect(zymbiote.payload_base, zymbiote.payload_size,
                          zymbiote.payload_original_protection);
    }
    else
    {
        (*env)->ReleaseStringUTFChars(env, name, name_utf8);
    }

    if (revert_now)
    {
        __attribute__((musttail))
        return rustfrida_stop_and_return_from_setargv0(env, clazz, name);
    }

    return 0;
}

/* ========== 等待 rustFrida 允许恢复 ========== */
static void
rustfrida_wait_for_permission_to_resume(const char *package_name, bool *revert_now)
{
    int fd;
    struct sockaddr_un addr;
    socklen_t addrlen;
    unsigned int name_len;

    *revert_now = false;

    fd = zymbiote.socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        goto beach;

    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';

    name_len = 0;
    for (unsigned int i = 0; i != sizeof(zymbiote.socket_path); i++)
    {
        if (zymbiote.socket_path[i] == '\0')
            break;

        if (1u + i >= sizeof(addr.sun_path))
            break;

        addr.sun_path[1u + i] = zymbiote.socket_path[i];
        name_len++;
    }

    addrlen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1u + name_len);

    if (rustfrida_connect(fd, (const struct sockaddr *)&addr, addrlen) == -1)
        goto beach;

    /* 发送 hello 消息: {pid, ppid, name_len, name} */
    {
        struct
        {
            uint32_t pid;
            uint32_t ppid;
            uint32_t package_name_len;
        } header;
        struct iovec iov[2];

        header.pid = zymbiote.getpid();
        header.ppid = zymbiote.getppid();

        header.package_name_len = 0;
        while (package_name[header.package_name_len] != '\0')
            header.package_name_len++;

        iov[0].iov_base = &header;
        iov[0].iov_len = sizeof(header);

        iov[1].iov_base = (void *)package_name;
        iov[1].iov_len = header.package_name_len;

        if (!rustfrida_sendmsg_all(fd, iov, 2, MSG_NOSIGNAL))
            goto beach;
    }

    /* 阻塞等待 ACK (1 字节 0x42) */
    {
        uint8_t rx;

        if (rustfrida_recv(fd, &rx, 1, 0) != 1)
            goto beach;
    }

    *revert_now = true;

beach:
    if (fd != -1)
        zymbiote.close(fd);
}

/* ========== 停止并从 setArgV0 返回 ========== */
/* raise(SIGSTOP) 用尾调用实现，确保栈帧正确 */
#define RUSTFRIDA_TAILCALL_TO_RAISE_SIGSTOP()                               \
    __asm__ __volatile__(                                                   \
        "mov    w0, #%[sig]\n"                                              \
                                                                            \
        "adrp   x16, zymbiote\n"                                            \
        "add    x16, x16, :lo12:zymbiote\n"                                 \
        "ldr    x16, [x16, %[raise_off]]\n"                                 \
                                                                            \
        "br     x16\n"                                                      \
      :                                                                     \
      : [sig] "i"(SIGSTOP),                                                 \
        [raise_off] "i"(offsetof(ZymbioteContext, raise))                    \
      : "x16", "memory"                                                     \
    )

__attribute__((naked, noinline))
static int
rustfrida_stop_and_return_from_setargv0(JNIEnv *env, jobject clazz, jstring name)
{
    RUSTFRIDA_TAILCALL_TO_RAISE_SIGSTOP();
}

/* ========== errno 辅助 ========== */
static int
rustfrida_get_errno(void)
{
    return *zymbiote.__errno();
}

/* ========== EINTR 安全的 socket 操作 ========== */
static int
rustfrida_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    for (;;)
    {
        if (zymbiote.connect(sockfd, addr, addrlen) == 0)
            return 0;

        if (rustfrida_get_errno() == EINTR)
            continue;

        return -1;
    }
}

static ssize_t
rustfrida_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    for (;;)
    {
        ssize_t n = zymbiote.sendmsg(sockfd, msg, flags);
        if (n != -1)
            return n;

        if (rustfrida_get_errno() == EINTR)
            continue;

        return -1;
    }
}

static bool
rustfrida_sendmsg_all(int sockfd, struct iovec *iov, size_t iovlen, int flags)
{
    size_t idx = 0;

    while (idx != iovlen)
    {
        struct msghdr m;

        m.msg_name = NULL;
        m.msg_namelen = 0;
        m.msg_iov = &iov[idx];
        m.msg_iovlen = iovlen - idx;
        m.msg_control = NULL;
        m.msg_controllen = 0;
        m.msg_flags = 0;

        ssize_t n = rustfrida_sendmsg(sockfd, &m, flags);
        if (n == -1)
            return false;

        size_t remaining = n;

        while (remaining != 0)
        {
            size_t avail = iov[idx].iov_len;

            if (remaining < avail)
            {
                iov[idx].iov_base = (char *)iov[idx].iov_base + remaining;
                iov[idx].iov_len -= remaining;
                remaining = 0;
            }
            else
            {
                remaining -= avail;
                idx++;
                if (idx == iovlen)
                    break;
            }
        }
    }

    return true;
}

static ssize_t
rustfrida_recv(int sockfd, void *buf, size_t len, int flags)
{
    for (;;)
    {
        ssize_t n = zymbiote.recv(sockfd, buf, len, flags);
        if (n != -1)
            return n;

        if (rustfrida_get_errno() == EINTR)
            continue;

        return -1;
    }
}

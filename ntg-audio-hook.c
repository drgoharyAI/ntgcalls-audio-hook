/*
 * ntg-audio-hook.c  --  Phase 5e
 *
 * Root cause (definitive, from disassembly of setupAudioPlaybackCallbacks):
 *   setupAudioPlaybackCallbacks navigates SM's tree (SM+0x28) to find an
 *   AudioReceiver (at tree_node+0x28), then calls AudioReceiver::onFrames on it
 *   to register the Python callback.  This AR ("sm_ar") is different from the
 *   AR that RemoteAudioSink::sendData dispatches to ("sendData_ar" at RAS+0x38).
 *   sendData_ar never has onFrames called -> AR+0xa0 = __create_empty -> dispatch
 *   check at 0x2ce912 always skips the Python callback -> silence on Asterisk side.
 *
 *   Key disassembly evidence (setupAudioPlaybackCallbacks 0x2f5b6c-0x2f5bd3):
 *     0x2f5b6c: r15 = found_node[0x28]  (AR from SM tree)
 *     0x2f5b75: vtable check (AudioReceiver vtable = base+0x24936a8)
 *     0x2f5bd0: rdi = r15               (this = AR from SM tree)
 *     0x2f5bd3: call AudioReceiver::onFrames  (0x2ce420)
 *
 *   Key disassembly evidence (AudioReceiver::onFrames 0x2ce420-0x2ce4bf):
 *     Calls new_policy[0](buf0) to CLONE the data before storing.
 *     No ownership transfer -- caller retains its copy.
 *
 * Fix (Phase 5d+5e):
 *   After setupAudioPlaybackCallbacks runs (via trampoline), traverse SM's tree
 *   (SM+0x28) to find sm_ar (the AR that received the callback).  Save it.
 *   On the first sendData call, if sendData_ar != sm_ar and sendData_ar has no
 *   callback: call AudioReceiver::onFrames(sendData_ar, &fn) where fn is built
 *   from sm_ar+0x88..0xa7.  onFrames clones the data, so both ARs get independent
 *   copies of the Python callback.
 *
 *   Phase-5e adds two more fixes needed for the dispatch to proceed:
 *   1. AR+0x40 (has_value of optional<AudioDescription> stored at AR+0x10) must be 1.
 *      The dispatch at 0x2ce6d1 checks this before calling the Python callback.
 *      Fix: call AudioSink::setConfig(sendData_ar, sm_ar+0x10) to copy the audio
 *      description from sm_ar (where it was set during normal init).
 *   2. AR+0x80 (weak_ptr control block for shared_ptr<RemoteAudioSink>) must be non-null.
 *      The dispatch at 0x2ce6dd checks this and calls weak_ptr::lock() on it.
 *      Fix: call AudioReceiver::open(sendData_ar) to create a new RAS and store its
 *      shared_ptr at AR+0x78/0x80.  open() does NOT write to AR+0x88..AR+0xa8
 *      (the Python callback area), so the transferred callback is preserved.
 *
 * Key offsets (confirmed by disassembly):
 *   NNI+0x15e = audioIncoming flag
 *   NNI+0x2b0 = RemoteAudioSink* (sink after addIncomingAudioTrack)
 *   NNI+0x3a0 = IAC map __begin_node_
 *   NNI+0x3a8 = IAC map __end_node_ (sentinel)
 *   NNI+0x3b0 = IAC map size
 *   vtable slot +0x50 = NativeNetworkInterface::enableAudioIncoming (0x32f4c0)
 *
 *   createChannels PLT:                  0x1f95d0
 *   createChannels:                      0x3285d0
 *   addIncomingSmartSource PLT:          0x1f38d0
 *   addIncomingSmartSource:              0x32dbb0
 *   NetworkInterface::enableAudioIncoming: 0x334f40 (PLT: 0x1f8430, GOT: 0x24fba18)
 *   NativeNetworkInterface::enableAudioIncoming: 0x32f4c0 (vtable slot +0x50)
 *   setupAudioPlaybackCallbacks:         0x2f5a30
 *   RemoteAudioSink::sendData:           0x31b250
 *   AudioReceiver::onFrames:             0x2ce420
 *   AudioSink::setConfig:                0x2cec70  (rdi=this, rsi=const optional<AudioDescription>*)
 *   AudioReceiver::open:                 0x2ce4f0  (rdi=this; writes AR+0x78/0x80, not AR+0x88..0xa8)
 *   __create_empty policy:               0x248f358  (+0x10 byte = 0x01 -> is_null)
 *   AudioReceiver vtable pointer:        base+0x24936a8
 *   AudioReceiver layout:
 *     +0x88..0xa8: std::function<on_frames>  (registered by AudioReceiver::onFrames)
 *       +0x88: __buf_[0]   +0x90: __buf_[1]
 *       +0x98: __call_func +0xa0: __policy_  (if == 0x248f358 -> empty -> never called)
 *   RemoteAudioSink layout:
 *     +0x18: batch_size   +0x20/0x28/0x30: vector
 *     +0x38: policy_storage[0] = AudioReceiver*
 *     +0x48: __call_func (open()::$_0 dispatcher)
 *   SM tree (at SM+0x28):
 *     root = *(SM+0x28); each node: [+0x00]=parent [+0x08]=left [+0x10]=right
 *     [+0x18]=is_black [+0x20]=pair<Mode,Device> key [+0x28]=AudioReceiver* value
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <execinfo.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <errno.h>

/* -- Base address resolution -------------------------------------------- */

static uintptr_t g_ntgcalls_base = 0;

static uintptr_t get_ntgcalls_base(void) {
    if (g_ntgcalls_base) return g_ntgcalls_base;

    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "ntgcalls.cpython")) {
            char *endptr;
            uintptr_t base = (uintptr_t)strtoull(line, &endptr, 16);
            if (*endptr == '-') {
                g_ntgcalls_base = base;
                break;
            }
        }
    }
    fclose(f);
    return g_ntgcalls_base;
}

/* -- SIGABRT handler ----------------------------------------------------- */

static struct sigaction g_old_sigabrt;

static void sigabrt_handler(int sig, siginfo_t *info, void *ctx)
{
    (void)sig; (void)info; (void)ctx;

    void *bt[64];
    int   n = backtrace(bt, 64);
    char **syms = backtrace_symbols(bt, n);

    fprintf(stderr, "\n[ntg-hook] === SIGABRT backtrace (%d frames) ===\n", n);

    uintptr_t base = g_ntgcalls_base;
    for (int i = 0; i < n; i++) {
        uintptr_t addr = (uintptr_t)bt[i];
        if (base && addr >= base && addr < base + 0x4000000) {
            fprintf(stderr, "  [%2d] ntgcalls+0x%lx  %s\n",
                    i, (unsigned long)(addr - base), syms ? syms[i] : "?");
        } else {
            fprintf(stderr, "  [%2d] 0x%lx  %s\n",
                    i, (unsigned long)addr, syms ? syms[i] : "?");
        }
    }
    fprintf(stderr, "[ntg-hook] === end backtrace ===\n");
    fflush(stderr);
    free(syms);

    sigaction(SIGABRT, &g_old_sigabrt, NULL);
    raise(SIGABRT);
}

__attribute__((constructor))
static void install_sigabrt_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigabrt_handler;
    sa.sa_flags     = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGABRT, &sa, &g_old_sigabrt);
    fprintf(stderr, "[ntg-hook] Phase-5e loaded -- SIGABRT handler installed\n");
    fflush(stderr);
}

/* -- Re-entrancy guard --------------------------------------------------- */
static atomic_int g_force_creating = 0;

/* -- Python->C signal: PLAYBACK(SHELL) configured ----------------------- */
static atomic_int g_playback_shell_configured = 0;

/* -- Last known NNI pointer --------------------------------------------- */
static void *g_last_nni = NULL;

/* -- RemoteAudioSink::sendData inline hook ------------------------------ */
static void    *g_senddata_trampoline = NULL;
static atomic_int g_senddata_count    = 0;
static atomic_int g_senddata_installed = 0;

/* -- setupAudioPlaybackCallbacks inline hook ---------------------------- */
#define SETUP_PB_OFFSET     0x2f5a30UL
#define EMPTY_POLICY_OFFSET 0x248f358UL   /* __create_empty policy; +0x10 byte = 0x01 */
#define AR_VTABLE_OFFSET    0x24936a8UL   /* _ZTVN8ntgcalls13AudioReceiverE+0x10 */

static void   *g_setup_pb_trampoline  = NULL;
static atomic_int g_setup_pb_installed = 0;
static atomic_int g_setup_pb_retried   = 0;

/* Saved args from setupAudioPlaybackCallbacks invocation */
static void   *g_last_pb_sm    = NULL;
static void   *g_last_pb_adesc = NULL;
static int     g_last_pb_flag  = 0;
/* The AR from SM's tree that received the callback via onFrames */
static void   *g_last_pb_sm_ar = NULL;

/* forward declarations */
static int iac_map_empty(uint8_t *nni8);
static void my_senddata_hook(void *this_ptr, void *frames);
static void my_setup_pb_hook(void *sm, void *adesc, int flag);
static void install_setup_pb_hook(uintptr_t base);

/* -- IAC entry count from the red-black tree size field at NNI+0x3b0 --- */
static uint64_t iac_count(uint8_t *nni8) {
    return *(uint64_t *)(nni8 + 0x3b0);
}

/* Called from Python (ctypes) at the start of each new call. */
__attribute__((visibility("default")))
void ntg_hook_call_start(void)
{
    atomic_store(&g_playback_shell_configured, 0);
    atomic_store(&g_force_creating, 0);
    atomic_store(&g_senddata_count, 0);
    atomic_store(&g_setup_pb_retried, 0);
    g_last_nni      = NULL;
    g_last_pb_sm    = NULL;
    g_last_pb_adesc = NULL;
    g_last_pb_flag  = 0;
    g_last_pb_sm_ar = NULL;
    fprintf(stderr, "[ntg-hook] call_start: state reset\n");
    fflush(stderr);

    /* Install the setupAudioPlaybackCallbacks inline hook NOW, before Python
     * calls set_stream_sources(PLAYBACK, EXTERNAL).  handlePlaybackConfig fires
     * during set_stream_sources and calls setupAudioPlaybackCallbacks -- if the
     * hook is not in place yet we miss the SM/adesc/flag capture entirely. */
    uintptr_t base = get_ntgcalls_base();
    if (base) {
        install_setup_pb_hook(base);
    }
}

/* Called from Python (ctypes) after CONNECTED.  Not actively used in the
 * current flow but kept for compatibility. */
__attribute__((visibility("default")))
void ntg_hook_force_transport_registration(void)
{
    uintptr_t base = get_ntgcalls_base();
    if (!base || !g_last_nni) {
        fprintf(stderr, "[ntg-hook] force_transport_reg: base=%p nni=%p -- skipping\n",
                (void *)base, g_last_nni);
        fflush(stderr);
        return;
    }
    if (atomic_load(&g_force_creating)) {
        fprintf(stderr, "[ntg-hook] force_transport_reg: re-entrancy guard -- skipping\n");
        fflush(stderr);
        return;
    }
    uint8_t *nni8     = (uint8_t *)g_last_nni;
    void    *transport = *(void **)(nni8 + 0x370);
    int      is_empty  = iac_map_empty(nni8);

    fprintf(stderr,
        "[ntg-hook] force_transport_reg NNI=%p transport=%p IAC=%s sink=%p\n",
        g_last_nni, transport,
        is_empty ? "empty" : "has-entries",
        *(void **)(nni8 + 0x2b0));
    fflush(stderr);

    if (!transport) {
        fprintf(stderr, "[ntg-hook] force_transport_reg: transport NULL -- cannot create IAC yet\n");
        fflush(stderr);
        return;
    }

    atomic_store(&g_force_creating, 1);

    if (is_empty) {
        fprintf(stderr,
            "[ntg-hook] force_transport_reg: IAC empty + transport valid -- creating IAC via createChannels\n");
        fflush(stderr);
        nni8[0x15e] = 1;
        typedef void (*create_fn)(void *);
        ((create_fn)(base + 0x3285d0))(g_last_nni);

        int created = !iac_map_empty(nni8);
        fprintf(stderr,
            "[ntg-hook] force_transport_reg: after createChannels IAC=%s flag=%d\n",
            created ? "CREATED OK" : "STILL EMPTY (bug!)", nni8[0x15e]);
        fflush(stderr);
    } else {
        uint64_t cnt_before = iac_count(nni8);
        fprintf(stderr,
            "[ntg-hook] force_transport_reg: IAC has-entries (count=%llu) -- skipping recreation\n",
            (unsigned long long)cnt_before);
        fflush(stderr);
    }

    atomic_store(&g_force_creating, 0);
}

/* Called from Python (ctypes) after set_stream_sources(PLAYBACK, SHELL) succeeds. */
__attribute__((visibility("default")))
void ntg_hook_set_playback_configured(void)
{
    atomic_store(&g_playback_shell_configured, 1);
    fprintf(stderr, "[ntg-hook] PLAYBACK(SHELL) configured -- IAC creation armed\n");
    fflush(stderr);
}

/* -- IAC map empty check ------------------------------------------------- */
static int iac_map_empty(uint8_t *nni8) {
    void *begin = *(void **)(nni8 + 0x3a0);
    return (begin == (void *)(nni8 + 0x3a0) ||
            begin == (void *)(nni8 + 0x3a8));
}

/* -- AudioReceiver callback registration check -------------------------- */
static int ar_callback_registered(uint8_t *ar, uintptr_t base)
{
    if (!ar || !base) return 0;
    void *policy = *(void **)(ar + 0xa0);
    return ((uintptr_t)policy != (base + EMPTY_POLICY_OFFSET));
}

/* -- Retry setupAudioPlaybackCallbacks to register Python callback ------ */
static void try_register_playback_callback(void *ar_ptr, uintptr_t base)
{
    if (atomic_exchange(&g_setup_pb_retried, 1)) return;

    if (!g_setup_pb_trampoline) {
        fprintf(stderr, "[ntg-hook] retry_cb: setup_pb hook not installed\n");
        fflush(stderr);
        return;
    }
    if (!g_last_pb_sm) {
        fprintf(stderr, "[ntg-hook] retry_cb: no saved SM* -- setupPBCallbacks never captured\n");
        fflush(stderr);
        return;
    }

    void *ctrl_before = *(void **)((uint8_t *)g_last_pb_sm + 0x08);
    if (!g_last_pb_adesc) {
        fprintf(stderr, "[ntg-hook] retry_cb: adesc NULL -- skip unsafe retry\n");
        fflush(stderr);
        return;
    }

    fprintf(stderr,
        "[ntg-hook] retry_cb: SM=%p ctrl=%p adesc=%p flag=%d ar=%p\n",
        g_last_pb_sm, ctrl_before, g_last_pb_adesc, g_last_pb_flag, ar_ptr);

    if (ar_ptr && base) {
        void *pol_before = *(void **)((uint8_t *)ar_ptr + 0xa0);
        void *fn_before  = *(void **)((uint8_t *)ar_ptr + 0x98);
        fprintf(stderr,
            "[ntg-hook] retry_cb: ar+0x98=%p ar+0xa0=%p (registered_before=%d)\n",
            fn_before, pol_before,
            (uintptr_t)pol_before != (base + EMPTY_POLICY_OFFSET));
    }
    if (ctrl_before && base) {
        void *cpol = *(void **)((uint8_t *)ctrl_before + 0xa0);
        void *cfn  = *(void **)((uint8_t *)ctrl_before + 0x98);
        fprintf(stderr,
            "[ntg-hook] retry_cb: ctrl+0x98=%p ctrl+0xa0=%p (ctrl_registered=%d)\n",
            cfn, cpol,
            (uintptr_t)cpol != (base + EMPTY_POLICY_OFFSET));
    }
    fflush(stderr);

    typedef void (*fn_t)(void *, void *, int);
    ((fn_t)g_setup_pb_trampoline)(g_last_pb_sm, g_last_pb_adesc, g_last_pb_flag);

    int registered = ar_ptr ? ar_callback_registered((uint8_t *)ar_ptr, base) : -1;
    void *policy   = ar_ptr ? *(void **)(((uint8_t *)ar_ptr) + 0xa0) : NULL;
    void *call_fn  = ar_ptr ? *(void **)(((uint8_t *)ar_ptr) + 0x98) : NULL;
    fprintf(stderr,
        "[ntg-hook] retry_cb result: ar=%p +0x98=%p +0xa0=%p registered=%d\n",
        ar_ptr, call_fn, policy, registered);
    fflush(stderr);
}

/* -- AR vtable / tree helpers for Phase-5d callback transfer ------------ */

static int ar_has_vtable(uint8_t *ar, uintptr_t base) {
    if (!ar || !base) return 0;
    void *vptr = *(void **)ar;
    return ((uintptr_t)vptr == base + AR_VTABLE_OFFSET);
}

static void *find_sm_ar_with_callback(void *sm, uintptr_t base) {
    if (!sm || !base) return NULL;
    void *root = *(void **)((uint8_t *)sm + 0x28);
    if (!root) return NULL;

    void *stk[16];
    int sp = 0;
    stk[sp++] = root;
    while (sp > 0) {
        uint8_t *node = (uint8_t *)stk[--sp];
        if (!node) continue;
        void *ar_raw = *(void **)(node + 0x28);
        if (ar_raw) {
            uint8_t *ar = (uint8_t *)ar_raw;
            if (ar_has_vtable(ar, base) && ar_callback_registered(ar, base))
                return ar;
        }
        void *left  = *(void **)(node + 0x08);
        void *right = *(void **)(node + 0x10);
        if (sp < 14) {
            if (right) stk[sp++] = right;
            if (left)  stk[sp++] = left;
        }
    }
    return NULL;
}

static void transfer_ar_callback(uint8_t *dst_ar, uint8_t *src_ar, uintptr_t base) {
    struct {
        uint64_t buf0;
        uint64_t buf8;
        void    *call_func;
        void    *policy;
    } fn;

    fn.buf0      = *(uint64_t *)(src_ar + 0x88);
    fn.buf8      = *(uint64_t *)(src_ar + 0x90);
    fn.call_func = *(void **)   (src_ar + 0x98);
    fn.policy    = *(void **)   (src_ar + 0xa0);

    fprintf(stderr,
        "[ntg-hook] transfer_ar_callback: src=%p dst=%p\n"
        "  fn.buf0=%016lx fn.buf8=%016lx\n"
        "  fn.call_func=%p (ntgcalls+0x%lx) fn.policy=%p\n",
        src_ar, dst_ar,
        (unsigned long)fn.buf0, (unsigned long)fn.buf8,
        fn.call_func,
        (base && (uintptr_t)fn.call_func >= base)
            ? (unsigned long)((uintptr_t)fn.call_func - base) : 0UL,
        fn.policy);
    fflush(stderr);

    typedef void (*on_frames_fn)(void *, void *);
    ((on_frames_fn)(base + 0x2ce420))(dst_ar, &fn);

    int reg = ar_callback_registered(dst_ar, base);
    fprintf(stderr,
        "[ntg-hook] transfer_ar_callback done: dst+0xa0=%p registered=%d\n",
        *(void **)(dst_ar + 0xa0), reg);
    fflush(stderr);
}

/* -- setupAudioPlaybackCallbacks inline hook ---------------------------- */

static void install_setup_pb_hook(uintptr_t base)
{
    if (atomic_exchange(&g_setup_pb_installed, 1)) return;

    uintptr_t target = base + SETUP_PB_OFFSET;

    void *tramp = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        fprintf(stderr, "[ntg-hook] setup_pb hook: mmap failed: %s\n", strerror(errno));
        fflush(stderr);
        atomic_store(&g_setup_pb_installed, 0);
        return;
    }

    /*
     * Stolen bytes (14 = complete instructions from prologue):
     *   55          push %rbp
     *   41 57       push %r15
     *   41 56       push %r14
     *   41 55       push %r13
     *   41 54       push %r12
     *   53          push %rbx
     *   48 83 ec 38 sub  $0x38,%rsp
     */
    static const uint8_t stolen[14] = {
        0x55,
        0x41,0x57,
        0x41,0x56,
        0x41,0x55,
        0x41,0x54,
        0x53,
        0x48,0x83,0xec,0x38
    };
    uint8_t *t = (uint8_t *)tramp;
    memcpy(t, stolen, 14);
    uintptr_t resume = target + 14;
    t[14] = 0x48; t[15] = 0xb8;
    memcpy(t + 16, &resume, 8);
    t[24] = 0xff; t[25] = 0xe0;
    g_setup_pb_trampoline = tramp;

    uintptr_t page = target & ~0xfffUL;
    if (mprotect((void *)page, 8192, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "[ntg-hook] setup_pb hook: mprotect RWX failed: %s\n", strerror(errno));
        fflush(stderr);
        munmap(tramp, 4096);
        g_setup_pb_trampoline = NULL;
        atomic_store(&g_setup_pb_installed, 0);
        return;
    }
    uint8_t   *code      = (uint8_t *)target;
    uintptr_t  hook_addr = (uintptr_t)my_setup_pb_hook;
    code[0] = 0xff; code[1] = 0x25;
    code[2] = 0x00; code[3] = 0x00; code[4] = 0x00; code[5] = 0x00;
    memcpy(code + 6, &hook_addr, 8);
    mprotect((void *)page, 8192, PROT_READ | PROT_EXEC);

    fprintf(stderr,
        "[ntg-hook] setupPBCallbacks hook installed at %p trampoline=%p resume=%p\n",
        (void *)target, tramp, (void *)resume);
    fflush(stderr);
}

static void my_setup_pb_hook(void *sm, void *adesc, int flag)
{
    g_last_pb_sm    = sm;
    g_last_pb_adesc = adesc;
    g_last_pb_flag  = flag;

    uintptr_t base = get_ntgcalls_base();

    void *ctrl = sm ? *(void **)((uint8_t *)sm + 0x08) : NULL;
    fprintf(stderr,
        "[ntg-hook] setupPBCallbacks SM=%p ctrl=%p adesc=%p flag=%d\n",
        sm, ctrl, adesc, flag);
    fflush(stderr);

    typedef void (*fn_t)(void *, void *, int);
    ((fn_t)g_setup_pb_trampoline)(sm, adesc, flag);

    void *ctrl_after = sm ? *(void **)((uint8_t *)sm + 0x08) : NULL;

    if (ctrl) {
        void *sm_ar = find_sm_ar_with_callback(sm, base);
        g_last_pb_sm_ar = sm_ar;

        int sm_ar_reg = sm_ar ? ar_callback_registered((uint8_t *)sm_ar, base) : -1;
        fprintf(stderr,
            "[ntg-hook] setupPBCallbacks done (early_return=no)\n"
            "  SM=%p ctrl=%p sm_ar=%p sm_ar_registered=%d\n",
            sm, ctrl, sm_ar, sm_ar_reg);
        fflush(stderr);

        atomic_store(&g_setup_pb_retried, 1);
    } else {
        fprintf(stderr,
            "[ntg-hook] setupPBCallbacks done ctrl=NULL->%p (early_return=yes -- retry pending)\n",
            ctrl_after);
    }
    fflush(stderr);
}

/* -- RemoteAudioSink::sendData hook ------------------------------------- */

static void install_senddata_hook(uintptr_t base)
{
    if (atomic_exchange(&g_senddata_installed, 1)) return;

    uintptr_t target = base + 0x31b250;

    void *tramp = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) {
        fprintf(stderr, "[ntg-hook] sendData hook: mmap failed: %s\n", strerror(errno));
        fflush(stderr);
        atomic_store(&g_senddata_installed, 0);
        return;
    }

    /* Stolen bytes (12): push r15 / push r14 / push rbx / sub $0x30,%rsp / mov %rdi,%rbx */
    static const uint8_t stolen[12] = {
        0x41,0x57,
        0x41,0x56,
        0x53,
        0x48,0x83,0xec,0x30,
        0x48,0x89,0xfb
    };
    uint8_t *t = (uint8_t *)tramp;
    memcpy(t, stolen, 12);
    uintptr_t resume = target + 12;
    t[12] = 0x48; t[13] = 0xb8;
    memcpy(t + 14, &resume, 8);
    t[22] = 0xff; t[23] = 0xe0;
    g_senddata_trampoline = tramp;

    uintptr_t page = target & ~0xfffUL;
    if (mprotect((void *)page, 8192, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "[ntg-hook] sendData hook: mprotect RWX failed: %s\n", strerror(errno));
        fflush(stderr);
        munmap(tramp, 4096);
        g_senddata_trampoline = NULL;
        atomic_store(&g_senddata_installed, 0);
        return;
    }
    uint8_t   *code      = (uint8_t *)target;
    uintptr_t  hook_addr = (uintptr_t)my_senddata_hook;
    code[0] = 0x48; code[1] = 0xb8;
    memcpy(code + 2, &hook_addr, 8);
    code[10] = 0xff; code[11] = 0xe0;
    mprotect((void *)page, 8192, PROT_READ | PROT_EXEC);

    fprintf(stderr,
        "[ntg-hook] sendData hook installed at %p trampoline=%p resume=%p\n",
        (void *)target, tramp, (void *)resume);
    fflush(stderr);
}

static void my_senddata_hook(void *this_ptr, void *frames)
{
    int count = atomic_fetch_add(&g_senddata_count, 1) + 1;

    uint8_t  *s          = (uint8_t *)this_ptr;
    uint8_t  *ar         = (uint8_t *)(*(void **)(s + 0x38));
    uintptr_t base       = get_ntgcalls_base();

    if (count <= 5 || count % 500 == 0) {
        void     *cb_ptr     = *(void **)(s + 0x48);
        uintptr_t cb_off     = (base && (uintptr_t)cb_ptr >= base)
                               ? (uintptr_t)cb_ptr - base : 0;
        void     *ar_policy  = ar ? *(void **)(ar + 0xa0) : (void*)-1;
        void     *ar_callfn  = ar ? *(void **)(ar + 0x98) : (void*)-1;
        int       cb_reg     = ar ? ar_callback_registered(ar, base) : -1;
        uint64_t ar_u38 = ar ? *(uint64_t *)(ar + 0x38) : 0;
        uint64_t ar_u40 = ar ? *(uint64_t *)(ar + 0x40) : 0;
        uint64_t ar_u48 = ar ? *(uint64_t *)(ar + 0x48) : 0;
        fprintf(stderr,
            "[ntg-hook] sendData #%d this=%p ar=%p\n"
            "  AR[+0x38]=0x%016lx [+0x40]=0x%016lx [+0x48]=0x%016lx\n"
            "  callback=%p (ntgcalls+0x%lx)\n"
            "  AR+0x98=%p AR+0xa0=%p cb_registered=%d\n",
            count, this_ptr, ar,
            (unsigned long)ar_u38, (unsigned long)ar_u40, (unsigned long)ar_u48,
            cb_ptr, (unsigned long)cb_off,
            ar_callfn, ar_policy, cb_reg);
        fflush(stderr);
    }

    if (count == 1 && ar && base) {
        uint8_t *sm_ar = (uint8_t *)g_last_pb_sm_ar;
        int sd_reg  = ar_callback_registered(ar, base);
        int sm_reg  = sm_ar ? ar_callback_registered(sm_ar, base) : -1;
        int ar_40   = (int)ar[0x40];
        int sm_ar40 = sm_ar ? (int)sm_ar[0x40] : -1;
        void *ar_80 = *(void **)(ar + 0x80);

        fprintf(stderr,
            "[ntg-hook] sendData #1 AR check:\n"
            "  sendData_ar=%p registered=%d ar[0x40]=%d ar[0x80]=%p\n"
            "  sm_ar=%p registered=%d sm_ar[0x40]=%d MATCH=%d\n",
            ar, sd_reg, ar_40, ar_80,
            sm_ar, sm_reg, sm_ar40,
            ((void *)ar == (void *)sm_ar));
        fflush(stderr);

        /* Phase-5d: transfer Python callback from sm_ar to sendData_ar */
        if (!sd_reg) {
            if (sm_ar && sm_ar != ar && sm_reg == 1) {
                transfer_ar_callback(ar, sm_ar, base);
            } else {
                try_register_playback_callback(ar, base);
            }
        }

        /* Phase-5e fix 1: ensure AR+0x40 == 1 (optional<AudioDescription> has_value).
         * Dispatch at 0x2ce6d1 bails if this byte is 0. */
        if (ar[0x40] == 0) {
            if (sm_ar && sm_ar[0x40] == 1) {
                fprintf(stderr,
                    "[ntg-hook] Phase-5e: setConfig(sendData_ar, &sm_ar[0x10])\n");
                fflush(stderr);
                typedef int (*setconfig_fn)(void *, void *);
                int chg = ((setconfig_fn)(base + 0x2cec70))(ar, sm_ar + 0x10);
                fprintf(stderr,
                    "[ntg-hook]   setConfig done: changed=%d ar[0x40]=%d\n",
                    chg, (int)ar[0x40]);
                fflush(stderr);
            } else {
                ar[0x40] = 1;
                fprintf(stderr,
                    "[ntg-hook] Phase-5e: forced ar[0x40]=1 (no sm_ar config available)\n");
                fflush(stderr);
            }
        }

        /* Phase-5e fix 2: ensure AR+0x80 != NULL (weak_ptr<RAS> control block).
         * Dispatch at 0x2ce6dd calls lock() on it; NULL -> immediate exit. */
        if (*(void **)(ar + 0x80) == NULL) {
            fprintf(stderr,
                "[ntg-hook] Phase-5e: open(sendData_ar) to init AR+0x78/0x80\n");
            fflush(stderr);
            typedef void (*open_fn)(void *);
            ((open_fn)(base + 0x2ce4f0))(ar);
            fprintf(stderr,
                "[ntg-hook]   open() done: ar+0x78=%p ar+0x80=%p\n",
                *(void **)(ar + 0x78), *(void **)(ar + 0x80));
            fflush(stderr);
        }

        fprintf(stderr,
            "[ntg-hook] sendData #1 AR final: registered=%d ar[0x40]=%d ar[0x80]=%p\n",
            ar_callback_registered(ar, base), (int)ar[0x40], *(void **)(ar + 0x80));
        fflush(stderr);
    }

    typedef void (*senddata_fn)(void *, void *);
    ((senddata_fn)g_senddata_trampoline)(this_ptr, frames);
}

/* -- mprotect helper: make a page writable, write, restore -------------- */
static int write_to_protected(void **slot, void *new_val)
{
    uintptr_t page = (uintptr_t)slot & ~0xfffUL;
    if (mprotect((void *)page, 4096, PROT_READ | PROT_WRITE) != 0) {
        fprintf(stderr, "[ntg-hook] mprotect RW failed at %p: %s\n",
                slot, strerror(errno));
        return -1;
    }
    *slot = new_val;
    mprotect((void *)page, 4096, PROT_READ);
    return 0;
}

/* =========================================================================
 * Vtable hook: NativeNetworkInterface::enableAudioIncoming
 * Diagnostic only -- passes through to the real function unchanged.
 * ========================================================================= */
static void my_nni_enableAudioIncoming(void *nni, int enable)
{
    uintptr_t base = get_ntgcalls_base();
    if (!base) return;

    uint8_t *nni8     = (uint8_t *)nni;
    uint8_t  flag_was = nni8[0x15e];
    void    *sink     = *(void **)(nni8 + 0x2b0);
    int      empty    = iac_map_empty(nni8);
    int      pb_cfg   = atomic_load(&g_playback_shell_configured);

    fprintf(stderr,
        "[ntg-hook] vtable::enableAudio NNI=%p enable=%d flag=%d sink=%p IAC=%s pb_cfg=%d\n",
        nni, enable & 1, flag_was, sink, empty ? "empty" : "has-entries", pb_cfg);
    fflush(stderr);

    typedef void (*nni_enable_fn)(void *, int);
    ((nni_enable_fn)(base + 0x32f4c0))(nni, enable);

    uint8_t flag_now  = nni8[0x15e];
    int     empty_now = iac_map_empty(nni8);
    fprintf(stderr,
        "[ntg-hook]   vtable::enableAudio done: flag=%d IAC=%s\n",
        flag_now, empty_now ? "empty" : "has-entries");
    fflush(stderr);
}

/* -- GOT + vtable patching ----------------------------------------------- */
#define GOT_ENABLE_AUDIO_OFFSET 0x24fba18UL
#define VTABLE_SLOT_AUDIO       10
#define NNI_ENABLE_AUDIO_OFFSET 0x32f4c0UL

static atomic_int g_got_patched    = 0;
static atomic_int g_vtable_patched = 0;

void _ZN4wrtc16NetworkInterface19enableAudioIncomingEb(void *nni, int enable);

static void do_patches(uintptr_t base, void *nni)
{
    install_senddata_hook(base);
    install_setup_pb_hook(base);

    if (!atomic_exchange(&g_got_patched, 1)) {
        void **got = (void **)(base + GOT_ENABLE_AUDIO_OFFSET);
        void  *old = *got;
        if (write_to_protected(got,
                (void *)_ZN4wrtc16NetworkInterface19enableAudioIncomingEb) == 0) {
            fprintf(stderr,
                "[ntg-hook] GOT patched: enableAudio %p -> hook\n", old);
            fflush(stderr);
        } else {
            atomic_store(&g_got_patched, 0);
        }
    }

    if (!atomic_exchange(&g_vtable_patched, 1)) {
        void **vtable = *(void ***)nni;
        void  *slot   = vtable[VTABLE_SLOT_AUDIO];
        void  *expect = (void *)(base + NNI_ENABLE_AUDIO_OFFSET);

        if (slot != expect) {
            fprintf(stderr,
                "[ntg-hook] WARNING: vtable[%d]=%p expected %p -- skipping vtable patch\n",
                VTABLE_SLOT_AUDIO, slot, expect);
            fflush(stderr);
            atomic_store(&g_vtable_patched, 0);
        } else if (write_to_protected(&vtable[VTABLE_SLOT_AUDIO],
                                       (void *)my_nni_enableAudioIncoming) == 0) {
            fprintf(stderr,
                "[ntg-hook] vtable[%d] patched: NNI::enableAudio %p -> hook\n",
                VTABLE_SLOT_AUDIO, slot);
            fflush(stderr);
        } else {
            atomic_store(&g_vtable_patched, 0);
        }
    }
}

/* =========================================================================
 * Hook 1 (PLT): NetworkInterface::enableAudioIncoming
 * ========================================================================= */
__attribute__((visibility("default")))
void _ZN4wrtc16NetworkInterface19enableAudioIncomingEb(void *nni, int enable)
{
    uintptr_t base = get_ntgcalls_base();
    if (!base) return;

    uint8_t *nni8      = (uint8_t *)nni;
    uint8_t  flag_prev = nni8[0x15e];

    typedef void (*enable_fn)(void *, int);
    ((enable_fn)(base + 0x334f40))(nni, enable);

    uint8_t flag_now  = nni8[0x15e];
    int     empty_now = iac_map_empty(nni8);

    fprintf(stderr,
        "[ntg-hook] PLT::enableAudio NNI=%p enable=%d flag %d->%d sink=%p IAC=%s\n",
        nni, enable & 1, flag_prev, flag_now,
        *(void **)(nni8 + 0x2b0),
        empty_now ? "empty" : "has-entries");
    fflush(stderr);
}

/* =========================================================================
 * Hook 3 (PLT): NativeConnection::createChannels  (PLT: 0x1f95d0)
 * ========================================================================= */
__attribute__((visibility("default")))
void _ZN4wrtc16NativeConnection14createChannelsEv(void *nni)
{
    uintptr_t base = get_ntgcalls_base();
    if (!base) return;

    do_patches(base, nni);
    g_last_nni = nni;

    uint8_t *nni8 = (uint8_t *)nni;

    uint8_t *cnc    = *(uint8_t **)(nni8 + 0x518);
    uint8_t *is_beg = cnc ? *(uint8_t **)(cnc + 0x90) : NULL;
    uint8_t *is_end = cnc ? *(uint8_t **)(cnc + 0x98) : NULL;
    int n_src = (is_beg && is_end && is_end > is_beg)
                ? (int)((is_end - is_beg) / 0x50) : 0;

    void    *sink  = *(void **)(nni8 + 0x2b0);
    uint8_t  flag  = nni8[0x15e];
    int      empty = iac_map_empty(nni8);
    int      pb_cfg = atomic_load(&g_playback_shell_configured);

    fprintf(stderr,
        "[ntg-hook] createChannels NNI=%p flag=%d n_src=%d sink=%p IAC=%s pb_cfg=%d\n",
        nni, flag, n_src, sink,
        empty ? "empty" : "has-entries", pb_cfg);
    if (n_src > 0)
        fprintf(stderr, "[ntg-hook]   source[0] ssrc=0x%08x\n",
                *(uint32_t *)(is_beg + 0x04));
    fflush(stderr);

    void *transport = *(void **)(nni8 + 0x370);
    fprintf(stderr, "[ntg-hook]   transport=%p\n", transport);
    fflush(stderr);

    int do_force = (sink != NULL && n_src > 0 && empty &&
                    !atomic_load(&g_force_creating));
    if (do_force) {
        fprintf(stderr, "[ntg-hook]   sink non-null + IAC empty -- forcing IAC via audioIncoming=1\n");
        fflush(stderr);
        nni8[0x15e] = 1;
    }

    typedef void (*create_fn)(void *);
    ((create_fn)(base + 0x3285d0))(nni);

    int empty_after = iac_map_empty(nni8);

    if (do_force) {
        if (!empty_after) {
            /* Reset flag so that on ICE restart enableAudioIncoming(true) via vtable
             * sees flag=0 != enable=1, doesn't early-return, and SRTP registration
             * happens correctly. Also prevents double-insert on next createChannels. */
            nni8[0x15e] = 0;
            fprintf(stderr,
                "[ntg-hook]   IAC CREATED OK count=%llu flag reset->0\n",
                (unsigned long long)iac_count(nni8));
        } else {
            nni8[0x15e] = 0;
            fprintf(stderr, "[ntg-hook]   IAC STILL EMPTY after force (bug!)\n");
        }
        fflush(stderr);
    } else if (empty && !empty_after) {
        fprintf(stderr, "[ntg-hook]   NTgCalls created IAC naturally (count=%llu)\n",
                (unsigned long long)iac_count(nni8));
        fflush(stderr);
    } else if (!empty && empty_after) {
        fprintf(stderr, "[ntg-hook]   NTgCalls cleared IAC map\n");
        fflush(stderr);
    }

    fprintf(stderr,
        "[ntg-hook] createChannels done NNI=%p flag=%d sink=%p IAC=%s count=%llu\n",
        nni, nni8[0x15e],
        *(void **)(nni8 + 0x2b0),
        iac_map_empty(nni8) ? "empty" : "has-entries",
        (unsigned long long)iac_count(nni8));
    fflush(stderr);
}

/* =========================================================================
 * Hook 2 (PLT): NativeNetworkInterface::addIncomingSmartSource  (PLT: 0x1f38d0)
 * ========================================================================= */
__attribute__((visibility("default")))
void _ZN4wrtc22NativeNetworkInterface22addIncomingSmartSourceERKNSt4__Cr12basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEERKNS_12MediaContentEb(
    void *nni,
    void *endpoint,
    void *media_content,
    int   force)
{
    uintptr_t base = get_ntgcalls_base();
    if (!base) return;

    uint8_t *nni8      = (uint8_t *)nni;
    uint8_t  incoming  = nni8[0x15e];
    uint32_t ssrc      = media_content ? *(uint32_t *)((uint8_t *)media_content + 0x04) : 0;
    int      type      = media_content ? *(int *)((uint8_t *)media_content + 0x00) : -1;
    int      eff_force = force & 1;
    int      upgraded  = 0;

    if (!eff_force && incoming) {
        eff_force = 1;
        upgraded  = 1;
    }

    fprintf(stderr,
        "[ntg-hook] addIncomingSmartSource NNI=%p type=%d ssrc=0x%08x "
        "force=%d->%d audioIncoming=%d\n",
        nni, type, ssrc, force & 1, eff_force, incoming);
    fflush(stderr);

    int      empty_before = iac_map_empty(nni8);
    uint64_t count_before = iac_count(nni8);

    /* Guard against duplicate insert into red-black tree (-> heap corruption -> SIGABRT).
     * This happens at CONNECTED when NNI::enableAudioIncoming(true) fires via vtable
     * after we already force-created the IAC entry pre-CONNECTED. */
    if (count_before > 0) {
        fprintf(stderr,
            "[ntg-hook] addIncomingSmartSource NNI=%p ssrc=0x%08x: "
            "IAC already has %llu entries -- skip duplicate\n",
            nni, ssrc, (unsigned long long)count_before);
        fflush(stderr);
        return;
    }

    typedef void (*smart_fn)(void *, void *, void *, int);
    smart_fn orig = (smart_fn)(base + 0x32dbb0);
    orig(nni, endpoint, media_content, eff_force);

    int      empty_after = iac_map_empty(nni8);
    uint64_t count_after = iac_count(nni8);
    void    *sink_now    = *(void **)(nni8 + 0x2b0);

    if (empty_before && !empty_after) {
        uint32_t src_count = sink_now
            ? *(uint32_t *)((uint8_t *)sink_now + 0x18) : 0;
        fprintf(stderr,
            "[ntg-hook]   IAC %s with sink=%p source_count=%u count=%llu\n",
            upgraded ? "CREATED (force-upgraded)" : "CREATED",
            sink_now, src_count, (unsigned long long)count_after);
    } else if (!empty_before && empty_after) {
        fprintf(stderr, "[ntg-hook]   IAC MAP CLEARED count=%llu->%llu\n",
                (unsigned long long)count_before, (unsigned long long)count_after);
    } else if (empty_before && empty_after) {
        fprintf(stderr, "[ntg-hook]   no IAC created (flag=%d type=%d)\n",
                incoming, type);
    } else {
        fprintf(stderr, "[ntg-hook]   IAC map unchanged/augmented count=%llu->%llu\n",
                (unsigned long long)count_before, (unsigned long long)count_after);
    }
    fflush(stderr);
}

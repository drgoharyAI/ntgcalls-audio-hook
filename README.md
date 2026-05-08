# ntgcalls-audio-hook

LD_PRELOAD hook that fixes one-way audio silence (Telegram caller → Asterisk) when using
[NTgCalls](https://github.com/pytgcalls/ntgcalls) 2.1.0 as a Telegram VoIP bridge.

Built by reverse-engineering `ntgcalls.cpython-311-x86_64-linux-gnu.so` to find two
independent root causes — both required to deliver audio from a Telegram P2P call into
an Asterisk AGI channel.

---

## The problem

In a setup where:
- NTgCalls handles Telegram P2P WebRTC audio
- A Python bridge calls `set_stream_sources(PLAYBACK, EXTERNAL)` and registers
  an `on_frames` callback to receive decoded PCM
- The PCM is forwarded to Asterisk over a socket

...the Asterisk side heard **complete silence** even when the Telegram caller was
speaking. The `_on_frames` Python callback was never invoked.

---

## Root cause analysis

All offsets are relative to the NTgCalls `.so` load base, confirmed by disassembly
of `ntgcalls.cpython-311-x86_64-linux-gnu.so` version 2.1.0.

### Bug 1 — AudioReceiver mismatch (Phase 5d)

`setupAudioPlaybackCallbacks` at `base+0x2f5a30` traverses the `StreamManager` tree
at `SM+0x28` to find an `AudioReceiver` (`sm_ar`), then calls:

```
AudioReceiver::onFrames(sm_ar, python_lambda)   # base+0x2ce420
```

This registers the Python `_on_frames` callback on `sm_ar`.

However, `RemoteAudioSink::sendData` at `base+0x31b250` reads its dispatch target from
`RAS+0x38` (`policy_storage[0]`) — a **different** `AudioReceiver` object (`sendData_ar`).
The callback is never registered on `sendData_ar`, so dispatch silently skips the Python
callback every time.

**Key disassembly evidence:**
```
; setupAudioPlaybackCallbacks 0x2f5b6c-0x2f5bd3
0x2f5b6c: r15 = found_node[0x28]   ; AR from SM tree
0x2f5b75: vtable check (= base+0x24936a8)
0x2f5bd0: rdi = r15                 ; this = sm_ar
0x2f5bd3: call AudioReceiver::onFrames (0x2ce420)

; RemoteAudioSink::sendData 0x31b250
movsxd r12, dword ptr [rdi+0x14]   ; batch_size
mov    rbx, [rdi+0x38]             ; sendData_ar = policy_storage[0]  <-- different AR
call   [rbx+0x48]                  ; open()::$_0 dispatcher
```

### Bug 2 — Dispatch guard `AR+0x40` (Phase 5e)

The dispatcher `open()::$_0` at `base+0x2ce6c0` checks two conditions before
calling the Python callback:

```asm
cmpb  $0x1, 0x40(%r12)   ; AR+0x40 = has_value of optional<AudioDescription>
jne   exit                ; silent exit if 0
mov   0x80(%r12), %rdi   ; AR+0x80 = weak_ptr<RemoteAudioSink> control block
je    exit                ; silent exit if null
```

`AR+0x40` is the `has_value` byte of an `optional<AudioDescription>` stored at `AR+0x10`.
This byte is set when `AudioSink::setConfig` is called on the AR — but `setConfig` was
never called on `sendData_ar`, leaving `AR+0x40 = 0`.

`AR+0x80` was already non-null (NTgCalls calls `AudioReceiver::open()` on `sendData_ar`
internally), so no action was needed for this field.

---

## The fix

Applied on the first `RemoteAudioSink::sendData` frame (count == 1):

**Step 1 — callback transfer (Phase 5d):**
Traverse `SM+0x28` tree to find `sm_ar` (the AR that received the Python callback via
`onFrames`). Call `AudioReceiver::onFrames(sendData_ar, &fn)` where `fn` is reconstructed
from `sm_ar+0x88..0xa7`. `onFrames` clones the data internally — both ARs get independent
copies of the Python callback with no double-free risk.

**Step 2 — dispatch guard (Phase 5e):**
Call `AudioSink::setConfig(sendData_ar, sm_ar+0x10)`. This runs `__assign_from()` which
copies `optional<AudioDescription>` from `sm_ar` into `sendData_ar`, setting `AR+0x40=1`.
`setConfig` does **not** touch `AR+0x88..0xa8` (the Python callback area), so Step 1 is
not disturbed.

---

## Key offsets (NTgCalls 2.1.0 x86_64)

| Symbol | Offset |
|--------|--------|
| `AudioReceiver` vtable | `base+0x24936a8` |
| `AudioReceiver::onFrames` | `base+0x2ce420` |
| `AudioSink::setConfig` | `base+0x2cec70` |
| `AudioReceiver::open()` | `base+0x2ce4f0` |
| `open()::$_0` dispatcher | `base+0x2ce6c0` |
| `setupAudioPlaybackCallbacks` | `base+0x2f5a30` |
| `RemoteAudioSink::sendData` | `base+0x31b250` |
| `__create_empty` policy | `base+0x248f358` |
| `NativeConnection::createChannels` | `base+0x3285d0` |
| `NativeNetworkInterface::addIncomingSmartSource` | `base+0x32dbb0` |
| `NetworkInterface::enableAudioIncoming` | `base+0x334f40` |

## AudioReceiver object layout

| Offset | Field |
|--------|-------|
| `+0x00` | vtable ptr |
| `+0x08` | counter (zeroed by `BaseSink::clear`) |
| `+0x10` | `optional<AudioDescription>` value start |
| `+0x40` | **`has_value` byte** — must be 1 for dispatch |
| `+0x50` | mutex |
| `+0x78` | `RemoteAudioSink*` raw ptr (weak_ptr raw) |
| `+0x80` | **`weak_ptr<RAS>` control block** — must be non-null |
| `+0x88` | Python callback `__buf_[0]` |
| `+0x90` | Python callback `__buf_[1]` |
| `+0x98` | Python callback `__call_func` |
| `+0xa0` | Python callback `__policy_` |
| `+0xa8` | callback mutex |
| `+0xe0` | `unique_ptr<Resampler>` |

---

## Build

```bash
git clone https://github.com/drgoharyAI/ntgcalls-audio-hook
cd ntgcalls-audio-hook
make
sudo make install
```

Requires: `gcc`, `glibc-devel`, x86_64 Linux.

---

## Deployment

Add `LD_PRELOAD` to the service that runs the Python NTgCalls bridge.

Example `systemd` override (`/etc/systemd/system/tg-bridge.service.d/hook.conf`):

```ini
[Service]
Environment="LD_PRELOAD=/usr/local/lib/ntg-audio-hook.so"
```

Then:
```bash
systemctl daemon-reload
systemctl restart tg-bridge
```

From Python, call the exported C functions at the right points in the call lifecycle:

```python
import ctypes
_ntg_hook = ctypes.CDLL("/usr/local/lib/ntg-audio-hook.so")

# Before set_stream_sources() — arms the setupPBCallbacks intercept
_ntg_hook.ntg_hook_call_start()

# After set_stream_sources(PLAYBACK, SHELL) succeeds
_ntg_hook.ntg_hook_set_playback_configured()

# After CONNECTED (optional, for manual IAC retry)
_ntg_hook.ntg_hook_force_transport_registration()
```

Diagnostic output goes to `stderr` (captured in the systemd journal and/or
`/var/log/asterisk/tg-bridge.log` if redirected).

---

## Verification

After deploying, a successful call produces log lines like:

```
[ntg-hook] sendData #1 AR check:
  sendData_ar=0x... registered=0 ar[0x40]=0 ar[0x80]=0x...
  sm_ar=0x... registered=1 sm_ar[0x40]=1 MATCH=0
[ntg-hook] transfer_ar_callback: src=0x... dst=0x...
[ntg-hook] transfer_ar_callback done: registered=1
[ntg-hook] Phase-5e: setConfig(sendData_ar, &sm_ar[0x10])
[ntg-hook]   setConfig done: changed=1 ar[0x40]=1
[ntg-hook] sendData #1 AR final: registered=1 ar[0x40]=1 ar[0x80]=0x...
```

And the Python callback fires:
```
_on_frames called: mode=PLAYBACK rms=6337.8
```

---

## Compatibility

All offsets are hard-coded for **NTgCalls 2.1.0** (`ntgcalls.cpython-311-x86_64-linux-gnu.so`).
If you are on a different version, you will need to re-derive the offsets using a
disassembler (Ghidra, IDA, Binary Ninja) by locating the symbols listed in the table above.

---

## License

MIT

# Blade OS v1 interfaces

Unofficial · by Kaan Ergün

This is the implemented development contract, not a release or hardware-coverage
claim. There are two separate callers: an installed sandboxed application and an
owner-paired companion. An application signature/grant does not provide companion
credentials. No arbitrary shell, trust-key provisioning or root grant is exposed
by the network protocol. The OS enforces privileges; this SDK packages bytes.

## First visible application

Build and verify `examples/hello` using the commands in the SDK README. The owner
must trust its Ed25519 publisher on Blade before installation. The management
companion uploads the package, shows the OS-verified identity and requested
permissions, then requires explicit installation approval. `hud` is bit 4,
`network` is bit 8 and `storage` is bit 16; grants must equal the signed manifest.
Camera (1), microphone (2) and root (32) are unavailable to normal market apps.
Root applications require the separate local owner CLI's explicit opt-in.

On the glasses, open **Uygulamalar**, select the enabled application and tap.
The hello script writes `payload/text/tr.txt` to stdout and exits. The glasses
retain its text until Back/Home. Back is a two-finger tap; Home is a three-finger
upward swipe. The phone manages HUD apps but cannot launch their foreground view.

The current HUD API is plain UTF-8 stdout, not a socket or framebuffer API:

- At most 512 bytes are displayed in seven lines. A long/truncated UTF-8 tail is
  clipped safely; the renderer's finite font may replace unsupported glyphs.
- A session may emit at most 4096 bytes. Beyond that it is stopped. LF is allowed;
  tabs become spaces. Other C0 controls, DEL and terminal escapes fail the session.
- stdin/stderr are `/dev/null`. No touch input, display descriptor, owner file
  descriptor or camera access is inherited. There are no application callbacks.
- Back/Home, incoming remote assistance, or loss of the HUD supervisor stops the
  exact foreground application and its descendants. It stays installed/enabled.
- Opening requires the displayed package SHA256 still to match. Update, disable
  and remove stop the running application; enable alone does not start it.

Normal applications run under their persistent UID in private mount/PID/IPC/UTS
namespaces, a read-only payload/root, no capabilities and a seccomp policy.
`network` explicitly shares the host network; without it there is no configured
external network. `storage` exposes only that app's persistent data; otherwise
data is an ephemeral 4 MiB filesystem. Programs can use BusyBox or static AArch64
ELF; only the libc/loader pair is supplied for dynamic ELF. There is no SDK camera
or microphone consumer API. Owner camera access below must not be silently
substituted for an unsupported application permission.

## Owner pairing and framing

TCP/TLS 1.2 or 1.3, default port 7443, on owner-selected interfaces. Before sending
AUTH, verify the exact DER leaf certificate SHA256 from the private pairing file.
The explicit pin is the trust anchor. Never log tokens, photos or instructions.

Camera pairing has exactly five fields: `protocol` (1), `host` (IPv4 string),
`port`, `certificate_sha256` (64 lowercase hex), `token` (64 lowercase hex).
Management pairing additionally has `kind: "blade-app-management"`. The two roles
use different random 32-byte tokens and the same certificate pin. A connection's
first message fixes its role. A token replacement only takes effect after a
controlled daemon stop/restart; changing a file alone does not revoke live access.

Every packet starts with 16 bytes, big endian:

```text
"BLD1" | version:u16=1 | type:u16 | request_id:u32 | payload_bytes:u32
```

Client IDs are positive and strictly increase per connection. Responses use
`type | 0x8000`, the same ID, and `status:u32` before their body. Push IDs are zero.
Statuses are 0 OK, 1 unauthorized, 2 invalid, 3 busy, 4 unknown session/application,
5 stale frame/offset/revision, 6 unavailable, 7 I/O or uncertain operation.
Errors contain only the status. Invalid framing/order/auth/length closes the
connection. Control payloads are at most 4096 bytes, except upload chunks below;
frame/photo packets are bounded by 1 MiB + 64 bytes. JPEG alone is at most 1 MiB.

## Camera and assistance role

Authenticate each connection with type 1 and raw token[32]. Use a persistent
control connection and a separate authenticated subscriber connection.

| Type | Request body | Success body after status |
|---|---|---|
| 2 STATUS | empty | JSON, at most 4092 bytes |
| 3 START | seconds:u32 (1..1800) | session[16] |
| 4 STOP | session[16] | empty |
| 5 SUBSCRIBE | session[16] | empty, then FRAME/END pushes |
| 6 FREEZE | session[16], frame_id:u64 | empty |
| 7 TEXT | session[16], frame_id:u64, length:u16, UTF-8[1..160] | empty |
| 8 ARROW | session[16], frame_id:u64, x0/y0/x1/y1:u16 | empty |
| 9 RESUME | session[16] | empty |
| 10 PHOTO | session[16] | frame_id:u64, SHA256[32], length:u32, JPEG |
| 11 PING | session[16] or empty | empty |

FRAME type `0x9001` is session[16], frame_id:u64, capture_monotonic_ns:u64,
width:u16, height:u16, jpeg_bytes:u32, JPEG. Initial geometry is 640×480.
Frame IDs strictly increase in one session; Blade monotonic time is not a phone
wall clock and does not establish optical latency. END `0x9002` contains
session[16], reason:u32 (0 stop, 1 deadline, 2 control lost, 3 camera error,
4 revoked); the stream then closes.

One control connection owns the camera. Send PING every five seconds; loss of
control, subscriber departure, 15 seconds without a valid PING, or the requested
deadline stops capture. Close sockets on cancellation/lifecycle loss, including
when a START reply was lost. Never automatically START again. FREEZE chooses a
retained frame or returns stale; TEXT/ARROW require that frozen ID. Coordinates
are 0..65535 across the uncropped image, excluding letterbox margins. RESUME
removes annotations. PHOTO reuses the latest JPEG and does not capture secretly.

STATUS JSON keys: `protocol`, `os_version`, `camera_available`, `session_active`,
`frame_width`, `frame_height`.

## Owner application management role

Authenticate with type 20 and its separate raw token[32]. No camera commands are
allowed in this role, and camera authority cannot manage apps.

| Type | Request body | Success body after status |
|---|---|---|
| 32 LIST | offset:u32 | list JSON |
| 33 BEGIN | package_bytes:u64, SHA256[32] | upload_id[16] |
| 34 CHUNK | upload_id[16], offset:u64, bytes[1..65536] | next_offset:u64 |
| 35 FINISH | upload_id[16] | verified preview JSON |
| 36 ABORT | upload_id[16] | empty |
| 37 INSTALL | upload_id[16], grants:u32, expected_revision[32] | install JSON |
| 38 ACTION | action:u8, id_bytes:u8, ASCII id, expected_revision[32] | action JSON |
| 39 STATUS | id_bytes:u8, ASCII id | application JSON |

IDs use the SDK grammar and at most 96 bytes. Actions are 1 enable, 2 disable,
3 launch, 4 remove/keep-data, 5 remove/delete-data. HUD launch returns unavailable;
open it on the glasses. Other launches return after actual exec readiness and
keep running after the phone disconnects. No mutation is automatically retried.

The package limit is 64 MiB, CHUNK payload limit 65560 bytes. One upload belongs
to its management connection; offsets must be exact. Its absolute lifetime is
300 seconds and idle limit 15 seconds. Only upload progress renews idle time;
STATUS does not. FINISH validates size/hash and the native signature, then renews
idle time. A single native operation has a 30-second deadline; clients may allow
35 seconds for its reply. An expired preview requires explicit reselection/upload.
Connection loss cleans staging, not an already committed install. After an
uncertain mutation reply, query STATUS instead of repeating the operation.

Expected revision is the current complete package SHA256, or 32 zero bytes for a
new/removed target. CAS is checked under the OS store lock. Trust keys and paths
are selected only by the OS owner, never by uploaded data or client arguments.

LIST is `{"items":[APP,...],"next_offset":number-or-null}`, at most eight rows
ordered by ID. Pages are current views, not a cross-request snapshot. APP has
`id`, `uid`, `version` (null when removed), `revision` (zero when removed),
`signer` (SPKI SHA256), `permissions` (mask), `run_as`, `enabled`, `installed`,
`running`. Preview has `id`, `version`, `revision`, `signer`, `permissions`,
`run_as`, `files`, `package_bytes`, `installable`. INSTALL returns `operation`,
`id`, `version`, `uid`; ACTION returns its operation record, with `id`, `uid`,
`worker` for launch. JSON bodies are at most 4092 bytes. Removed signer/UID records
can remain to protect retained data ownership. Owner-only root metadata may be
listed but cannot be changed through this management role.

## Shared compatibility fixture

[`bld1-v1.properties`](bld1-v1.properties) is the canonical language-neutral
constant and packet fixture. Tokens/session IDs in it are synthetic. OS C and
Android tests compare their actual serializers/constants against these exact
bytes; the Android test-resource copy must be byte-identical. A future iOS
implementation must use this same fixture before claiming protocol compatibility.
The fixture does not replace lifecycle, credential, malformed-input or hardware
tests. OS implementation references are `userspace/companion/protocol.{h,c}` and
`docs/{companion,market}-protocol.md`; incompatible changes require a deliberate
protocol/version decision across all consumers.

## Signed catalog interoperability

`tests/fixtures/catalog-v1.json` and `catalog-publisher.pem` are public fixtures
produced by the SDK CLI. The catalog signer and application publisher are
deliberately different. The Android test resources contain byte-identical copies
and verify them with platform Ed25519. Keep these fixture copies together when
changing the format; future Swift tests should consume the same bytes. The
fixture URL is synthetic and is never a hosted download service. No private
signing key is included.

A catalog consumer separately selects its catalog trust key, persists the highest
accepted revision plus its canonical hash, and rejects older or conflicting equal
revisions. Trusting a catalog must never add its package publishers to the OS
trust store. Before requesting installation, compare downloaded size/hash and the
OS-verified package identity, version, publisher, permissions and privilege level
with the signed entry. An explicit owner action is still required for installation.

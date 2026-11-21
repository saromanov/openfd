# JSON schemas

`openfd` streams NDJSON in `--json` / `-j` mode: one JSON object per line,
written as soon as the data is known. Two subcommands extend the row schema
with their own objects.

## `openfd why --json`

The output is a stream of **holder** objects followed by exactly one
**summary** object. The summary is always last, even when nothing holds the
target.

### holder

```json
{"type":"holder","pid":812,"start_time":1234567,"comm":"nginx","user":"www-data",
 "how":"fd","fd":7,"target":"/mnt/data/logs/access.log","deleted":false,
 "size":10485760,"lock":null,
 "sock":null,"owner":{"kind":"systemd_unit","name":"nginx.service",
 "cgroup":"/system.slice/nginx.service"},"namespace":false,"tty":null}
```

| Field | Type | Notes |
|---|---|---|
| `type` | string | Always `holder`. |
| `pid` | number | Submount holders have `pid: 0` and no process fields. |
| `start_time` | number? | `/proc/<pid>/stat` field 22: identifies a reused pid. |
| `comm` | string | `/proc/<pid>/comm`. |
| `user` | string | Username, or the uid with `-n`. |
| `how` | string | `fd`, `cwd`, `root`, `exe`, `mmap`, `lock` or `submount`. |
| `fd` | number? | Descriptor number for `how: fd`. |
| `target` | string | Path, socket endpoint or submount path. |
| `deleted` | bool | The file was unlinked while open. |
| `size` | number? | File size; for deleted files this is reclaimable space. |
| `lock` | object? | `{"kind":"POSIX","mode":"WRITE","pid":812,"inode":12345}`. |
| `sock` | object? | `{"proto":"TCP","local":"0.0.0.0:8080","remote":"10.0.0.5:40000","state":"LISTEN"}`. |
| `owner.kind` | string | `systemd_unit`, `user_session`, `user_service`, `docker`, `podman`, `containerd`, `k8s_pod` or `unknown`. |
| `owner.name` | string | Unit name, session label, pod uid or 12-char container id. |
| `owner.cgroup` | string | Raw cgroup path (empty with `--no-owner`). |
| `namespace` | bool | The holder lives in another mount namespace; `target` is `(ns)`-relative. |
| `tty` | string? | Controlling terminal, when known. |

Optional fields are omitted, never emitted as `null`.

### summary

```json
{"type":"summary","target":"/mnt/data","target_kind":"mount","fs":"ext4",
 "source":"/dev/sdb1","holders":4,"processes":3,"deleted_bytes":0,
 "time_wait":0,
 "hints":[{"owner":"nginx.service","command":"systemctl restart nginx.service",
 "reason":"holds fd 7"}],
 "incomplete":{"permission_denied":0}}
```

| Field | Type | Notes |
|---|---|---|
| `target_kind` | string | `file`, `dir`, `mount` or `port`. |
| `fs` / `source` | string? | Mount filesystem type and source, mount targets only. |
| `holders` | number | Every holder row, including submounts. |
| `processes` | number | Distinct pids (submounts do not count). |
| `deleted_bytes` | number | Total reclaimable bytes. |
| `time_wait` | number | TIME_WAIT sockets on the port (no owning process). |
| `hints` | array | Empty with `--no-hints`. Every hint has a `reason`; `alternative` is optional. |
| `incomplete.permission_denied` | number | Processes that could not be inspected. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | at least one holder found |
| `1` | nothing holds the target |
| `2` | error (bad target, `/proc` unavailable) |

## `openfd leak --json`

A stream of **leak** objects (one per leaking process, closest ETA first)
followed by exactly one **summary** object.

### leak

```json
{"type":"leak","pid":3120,"comm":"java","user":"sergey",
 "owner":{"kind":"systemd_unit","name":"orders.service"},
 "fds":8412,"limit":65536,"rate_per_min":38.2,"r2":0.97,
 "eta_seconds":89700,
 "verdict":"CLOSE-WAIT accumulation: the application never closes accepted sockets (check response and error paths)",
 "breakdown":[{"signature":"tcp -> 10.0.0.5 CLOSE-WAIT","delta":171}]}
```

| Field | Type | Notes |
|---|---|---|
| `type` | string | Always `leak`. |
| `pid` / `comm` / `user` | | Process identity; `user` is a name or the uid. |
| `owner` | object? | `{"kind":...,"name":...}`; omitted when unresolved. |
| `fds` | number | Latest fd count. |
| `limit` | number? | Soft `RLIMIT_NOFILE`; omitted when unreadable. |
| `rate_per_min` | number | Least-squares growth, fd per minute. |
| `r2` | number | Fit quality, `0.0`..=`1.0`. `>= 0.8` is reported as `steady`. |
| `eta_seconds` | number? | Seconds to `EMFILE` at the current rate (0 when already at the limit). |
| `verdict` | string | Likely bug for the dominant signature. |
| `breakdown` | array | Up to five `{"signature","delta"}` rows, largest growth first. |

### summary

```json
{"type":"summary","processes":312,"samples":30,"window_seconds":300,
 "leaking":1,"worst_eta_seconds":89700}
```

| Field | Type | Notes |
|---|---|---|
| `processes` | number | Peak number of processes observed in the window. |
| `samples` | number | Snapshots taken. |
| `window_seconds` | number | Measured wall-clock length of the window. |
| `leaking` | number | Reported leaks (after `--top`). |
| `worst_eta_seconds` | number? | Smallest ETA among the reported leaks. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | no leak detected |
| `1` | leak detected (growth above `--min-rate`) |
| `2` | error |
| `3` | `--fail-if-eta` threshold breached (takes priority over `1`) |

# Usage

```bash
docker run --rm -ti -p 3000:3000 nmaguiar/gcutils /bin/bash
```

```bash
docker run --rm -ti --pid=container:abc123ef456 --ipc=container:abc123ef456 nmaguiar/gcutils /bin/bash
```

> The original container might need to be started with the option "--ipc=shareable"

---

## ⚙️  Deploy using kubectl 

{{{$acolor 'FAINT,ITALIC' 'kubectl run gcutils --rm -it --image nmaguiar/gcutils -- /bin/bash'}}}

**Attach to a container to debug:**

{{{$acolor 'FAINT,ITALIC' 'kubectl debug pod-to-debug -it --image nmaguiar/gcutils --target=container-to-debug --profile=netadmin -- /bin/bash'}}}

Profiles:

| Profile | Description |
|---------|-------------|
| netadmin | Network Administrator privileges (NET_ADMIN and NET_RAW). |
| sysadmin | System Administrator (root) privileges. |
| general | A reasonable set of defaults tailored for each debuging journey (SYS_PTRACE). |
| auto | Automatically choose between general, baseline, and restricted. |

---

## Utils available in this image

| Utility | Use for | Usage help |
|---------|---------|------------|
| switch-fs-by-pid.sh | Switches to the filesystem of a provided pid. | |
| switch-user-by-pid.sh | Switches to the user of a provided pid. | |
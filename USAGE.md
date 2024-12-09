# Usage

```bash
docker run --rm -ti -p 3000:3000 nmaguiar/gcutils /bin/bash
```

```bash
docker run --rm -ti --pid=container:abc123ef456 --ipc=container:abc123ef456 nmaguiar/gcutils /bin/bash
```

> The original container might need to be started with the option "--ipc=shareable"

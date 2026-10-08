# The fence's gateway (4 October 2026)

The deep review of `sv` at `eff3f17` found that the network fence let the app reach the host (S2, high).
`docker network create --internal` stops traffic leaving for the internet. It still gives the bridge an address of
its own, the network's gateway, and that address is the host: this computer on Linux, or the virtual machine Docker
runs in on Docker Desktop and Colima. The review's fenced container reached the Colima machine's SSH server at
172.20.0.1:22 while 1.1.1.1 was blocked. `verify_fenced` only asked Docker whether the network was internal, and
the fence test only tried the internet. CI confirmed it on GitHub's Linux runners: on a plain `--internal` network,
the gateway answered.

- **The network has no gateway address.** It is created with `com.docker.network.bridge.gateway_mode_ipv4=isolated`
  (Docker 28 and later). Failing that it uses `com.docker.network.bridge.inhibit_ipv4=true`, and failing both the
  plain internal network, leaving the check below to decide. Containers on it still reach one another.
- **The run fails closed.** Before the app starts, a throwaway container on the fence (read-only, no capabilities)
  knocks with busybox's netcat on every gateway Docker names, and on each IPv4 subnet's first address, where a
  gateway would be: a network made without one names none.
  - A connection, or a refusal, is the host's stack answering, and the run stops. The message says which way the
    network was made.
  - A timeout, no route, or an unreachable network is the fence holding.
  - Anything else stops the run too.

  The control is the same knock on the container's own loopback, which must read as refused. An `nc` that cannot
  tell the two apart therefore stops the run instead of passing for a fence.
- **The fence test asks the runner's own check of both networks.** A plain `--internal` network must be refused:
  that is the positive control, without which a pass would prove nothing. One made as the runner makes it must pass.

**What CI taught, since this environment has no Docker daemon.** Every lesson came from a run being refused, never
from a fence passed in error, because the check fails closed:
1. A network made without a gateway address names no gateway at all, so the subnet's first address is knocked on
   too.
2. Busybox's netcat says nothing about a refused connection unless asked twice to be verbose (`nc_bloaty.c`: "if
   we're scanning at a one -v verbosity level, don't print refusals"). So it is run as `nc -vv`, without `-z`, and
   with nothing to send. The loopback control caught the silence twice.
3. With no gateway, Docker gives the subnet's first address to the first container on the network, which was the
   knocking container itself. Its own refusal read as the host answering. An address that is the knocking
   container's own is now not knocked on, and "every address was its own" is the fence holding.

`tests/interrupt.rs` now says what `sv` printed and its exit status when a run ends before starting, which is how
these were read.

**Tests.** The reading of the knocks has unit tests. Two breaks were each caught: a refusal read as the fence
holding, and the control left out. The fence tests ran for real in CI and passed.

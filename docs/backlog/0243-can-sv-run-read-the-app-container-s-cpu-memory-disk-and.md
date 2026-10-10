# Can sv run read the app container's CPU, memory, disk and egress from the host?

**Status:** open

From 0029, part 9 (C9.1.1). The AI probe records CPU, memory, disk and egress quotas as unchecked, because the app is judged from outside. `sv run` starts the app's container from the host, so the host may be able to read its resource use. Research first: find out whether the container backend reports these numbers for a running container and what it costs to read them. Build nothing until the answer is in this item.

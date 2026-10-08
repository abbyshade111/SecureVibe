# `sv` in a container

For somebody who will not install Rust, `Dockerfile` builds `sv` into an image their AI tool
starts through `.mcp.json`. It needs no change to the code: `sv` finds its data through the folder it
was compiled in, and inside the image that folder is the same for everyone. So the runtime image keeps
`crates/` as well as `data/`, since the paths run through `crates/<crate>/../../data`. Run with
`--network none`, the container makes the promise that `sv` opens no connection something enforced.

It does not do `sv report --run`. Starting the app means starting containers, and doing that from
inside a container means handing it the Docker socket, which is control of the owner's machine. That
step stays at a terminal with a native `sv`.

The test, `tools/image_smoke.py`, drives the image over MCP as a tool would, on an app with a `.env`
committed to git. It asserts the committed-secrets check ran before comparing the image with a native
`sv`, because the first attempt compared two runs in which neither had run the check and called that
agreement. It runs once more as root over a folder root does not own, because git refuses such a
repository and the check would otherwise be quietly *not assessed*. That is the witness for
`safe.directory`, and it can only exist on Linux, which is where CI runs it.

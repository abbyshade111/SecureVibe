# Dependencies `sv` declares it read, and cannot match

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026. A Go app
declaring and using `github.com/gorilla/websocket` had V4.4.1–V4.4.4 excluded as "No WebSocket
library is used": `go.mod` gives full module paths, the signatures named `gorilla/websocket`, and the
comparison was exact, so no Go package signature had ever matched. A Go signature now matches the
module path or its tail on a `/` boundary, with a `/vN` suffix set aside. Most Go names in both data
files were also wrong in themselves — `goth`, `stripe-go`, `go-openai` are not what `go.mod` says —
and are now module paths, with a test refusing a bare name; `autocert` is a package inside
`golang.org/x/crypto` and never appears in `go.mod`, so it is found in source instead. And
`build.gradle.kts`, the Kotlin default, is now read, for dependencies and for pinning.

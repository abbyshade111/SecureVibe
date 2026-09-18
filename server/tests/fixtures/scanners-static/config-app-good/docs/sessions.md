# How sign-in works

A signed-in visit is called a session. Sessions are tracked on the server; the browser only holds a random,
unguessable id.

| Setting | Value |
| --- | --- |
| Ends after no activity | 30 minutes |
| Ends no matter what, after | 12 hours |
| Devices signed in at once | 5 |

Signing out marks the session ended on the server immediately, so the id in the browser stops working even if the
cookie is not cleared.

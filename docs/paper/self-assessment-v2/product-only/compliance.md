# sv (SecureVibe) — what applies, and what is known

Produced by `sv`. ASVS level 1.

## The short version

252 things were found, worst first.

- **A shell command is built from a value** — high (ast.shell-command)
- **A shell command is built from a value** — high (ast.shell-command)
- **A shell command is built from a value** — high (ast.shell-command)
- **A shell command is built from a value** — high (ast.shell-command)
- **A value that looks like a credential is written into the code (`password`)** — high (secrets.credential-assignment)
- … and 247 more, in security.md, worst first

Of the requirements that apply to this app:

- **5** — something found a problem
- **7** — an automated check looked and found nothing wrong
- **87** — nothing has looked at these at all

### What to do next

1. Fix the 5 things that need attention. *(security.md lists each one with what to do)*
2. Answer the 30 questions at level 1 that no tool can settle — what your rules are, who may do what, how the app is built. 30 in all, most of them design review at higher levels. *(`sv notes` writes the questions out; the rest are the [design] section of securevibe.toml)*
3. Write tests for the 57 requirements a test could settle, starting with the 57 at level 1. *("Tests to write", lowest level first)*

## Read this first

99 requirements apply to this app. Of those, **12 have been looked at by something** and **87 have not**.

A further 19 about how the app is built with an AI coding tool, from OWASP AISVS Appendix C, are counted apart: see "How the app is built with AI", below.

There is no line in this report that says a requirement passed, because nothing here is able to establish that. A requirement marked *checked* had at least one automated check look at it and find nothing wrong, over the coverage named beside it — which is worth having and is not the same as the requirement being met. Everything else applicable is *not verified*: nothing has produced evidence either way.

| | count |
|---|---:|
| Applies, needs attention | 5 |
| Applies, checked by an automated check | 7 |
| Applies, you answered it in the security notes | 0 |
| Applies, not verified by anything | 87 |
| Does not apply | 52 |
| Not assessed — nobody has answered | 0 |
| Above this app's target level (ASVS level 1) | 470 |

## What was not examined

Each of these is a limit on what the rest of this report can mean.

| not examined | why |
|---|---|
| the running app | `sv report` does not start the app unless you pass --run. Without it, nothing here has asked the app anything — what it sends to a browser, what it says when something goes wrong, which sites it accepts. |
| what `codeql-javascript` would have found | CodeQL (JavaScript and TypeScript) is not installed on this computer, so nothing here has checked the javascript and typescript in this app the way it would have. Install it with `download the CodeQL bundle from https://github.com/github/codeql-action/releases, unpack it, and put its `codeql` on your PATH` and run this again. |
| the check `config.secrets-file-committed` | This folder is not a git repository, so `sv` cannot say whether a secrets file was ever committed. Putting the app in git (version control, which keeps every saved version) makes this check run, and is worth doing anyway. Ask your AI coding tool to do it, and to add a .gitignore that leaves out .env and other secret files before the first commit, so that commit does not save them. If the app is already kept in version control somewhere else, that copy's history is still unchecked. |
| 22 requirements that are design review, not scanning | these ask how the system was designed and how it is run — whether trust zones are enforced, whether an incident response plan is rehearsed, whether data has named owners. No check here reaches them and none ever will, so they are counted as applicable and unverified, and a person has to answer them. |
| 4 requirements that ask for a written decision | No tool can answer these: they ask what your rules are, who may do what, and how long things are kept. Run `sv notes` to write security-notes.md, answer the questions in it, and they become documented. Your AI coding tool can ask you them: `sv questions` prints them for its chat. |
| 4 questions about how this app is built | No tool can settle these — whether input is validated on the server, whether the app's own services authenticate to each other. Answer them in the [design] section of securevibe.toml: V2.2.2, V7.2.1, V8.3.1, V15.3.1. Your AI coding tool can ask you them: `sv questions` prints them for its chat. |

## Requirements that apply

### Level 1 — start here — 55 of them

| requirement | status | what it asks for |
|---|---|---|
| V1.2.5 | **needs attention** (ast.shell-command, ast.shell-command, ast.shell-command, ast.shell-command) | Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use contextual command line output encoding. |
| V11.4.1 | **needs attention** (ast.weak-hash-function) | Verify that only approved hash functions are used for general cryptographic use cases, including digital signatures, HMAC, KDF, and random bit generation. Disallowed hash functions, such as MD5, must not be used for any cryptographic purpose. |
| V4.4.1 | **needs attention** (semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket, semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket) | Verify that WebSocket over TLS (WSS) is used for all WebSocket connections. |
| V5.3.2 | **needs attention** (ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value, ast.file-path-from-value) | Verify that when the application creates file paths for file operations, instead of user-submitted filenames, it uses internally generated or trusted data, or if user-submitted filenames or file metadata must be used, strict validation and sanitization must be applied. This is to protect against path traversal, local or remote file inclusion (LFI, RFI), and server-side request forgery (SSRF) attacks. |
| V1.2.1 | not verified | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. |
| V1.2.2 | not verified | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). |
| V1.2.3 | not verified | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). |
| V1.3.1 | not verified | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. |
| V13.4.1 | not verified | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. |
| V14.2.1 | not verified | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. |
| V14.3.1 | not verified | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. |
| V15.1.1 | not verified | Verify that application documentation defines risk based remediation time frames for 3rd party component versions with vulnerabilities and for updating libraries in general, to minimize the risk from these components. |
| V15.3.1 | not verified | Verify that the application only returns the required subset of fields from a data object. For example, it should not return an entire data object, as some individual fields should not be accessible to users. |
| V2.1.1 | not verified | Verify that the application's documentation defines input validation rules for how to check the validity of data items against an expected structure. This could be common data formats such as credit card numbers, email addresses, telephone numbers, or it could be an internal data format. |
| V2.2.1 | not verified | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. |
| V2.2.2 | not verified | Verify that the application is designed to enforce input validation at a trusted service layer. While client-side validation improves usability and should be encouraged, it must not be relied upon as a security control. |
| V2.3.1 | not verified | Verify that the application will only process business logic flows for the same user in the expected sequential step order and without skipping steps. |
| V3.2.1 | not verified | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. |
| V3.2.2 | not verified | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. |
| V3.4.2 | not verified | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. |
| V3.5.1 | not verified | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). |
| V3.5.2 | not verified | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. |
| V3.5.3 | not verified | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. |
| V4.1.1 | not verified | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". |
| V5.2.1 | not verified | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. |
| V5.2.2 | not verified | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. |
| V5.3.1 | not verified | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. |
| V6.1.1 | not verified | Verify that application documentation defines how controls such as rate limiting, anti-automation, and adaptive response, are used to defend against attacks such as credential stuffing and password brute force. The documentation must make clear how these controls are configured and prevent malicious account lockout. |
| V6.2.1 | not verified | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. |
| V6.2.2 | not verified | Verify that users can change their password. |
| V6.2.3 | not verified | Verify that password change functionality requires the user's current and new password. |
| V6.2.4 | not verified | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. |
| V6.2.5 | not verified | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. |
| V6.2.6 | not verified | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. |
| V6.2.7 | not verified | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. |
| V6.2.8 | not verified | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. |
| V6.3.1 | not verified | Verify that controls to prevent attacks such as credential stuffing and password brute force are implemented according to the application's security documentation. |
| V6.3.2 | not verified | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. |
| V6.4.1 | not verified | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. |
| V6.4.2 | not verified | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. |
| V7.2.1 | not verified | Verify that the application performs all session token verification using a trusted, backend service. |
| V7.2.2 | not verified | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. |
| V7.2.3 | not verified | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. |
| V7.2.4 | not verified | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. |
| V7.4.1 | not verified | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. |
| V7.4.2 | not verified | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). |
| V8.1.1 | not verified | Verify that authorization documentation defines rules for restricting function-level and data-specific access based on consumer permissions and resource attributes. |
| V8.2.1 | not verified | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. |
| V8.2.2 | not verified | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). |
| V8.3.1 | not verified | Verify that the application enforces authorization rules at a trusted service layer and doesn't rely on controls that an untrusted consumer could manipulate, such as client-side JavaScript. |
| V1.2.4 | checked (ast.sql-built-by-hand: a database query joined together from text and values, rather than sent with its values kept separate, in 3 javascript files and 53 rust files) | Verify that data selection or database queries (e.g., SQL, HQL, NoSQL, Cypher) use parameterized queries, ORMs, entity frameworks, or are otherwise protected from SQL Injection and other database injection attacks. This is also relevant when writing stored procedures. |
| V1.3.2 | checked (ast.dynamic-code-execution: code built from a value and handed to something that runs it, such as eval, in 3 javascript files) | Verify that the application avoids the use of eval() or other dynamic code execution features such as Spring Expression Language (SpEL). Where there is no alternative, any user input being included must be sanitized before being executed. |
| V11.3.1 | checked (ast.weak-cipher: encryption in ECB mode, or with a retired cipher such as DES, triple DES, RC4, RC2, or Blowfish, in 3 javascript files and 53 rust files) | Verify that insecure block modes (e.g., ECB) and weak padding schemes (e.g., PKCS#1 v1.5) are not used. |
| V11.3.2 | checked (ast.weak-cipher: encryption in ECB mode, or with a retired cipher such as DES, triple DES, RC4, RC2, or Blowfish, in 3 javascript files and 53 rust files) | Verify that only approved ciphers and modes such as AES with GCM are used. |
| V15.2.1 | checked (advisories: all 68 packages in the bill of materials, compared against 2856 advisories) | Verify that the application only contains components which have not breached the documented update and remediation time frames. |

### Design review, which no tool settles at any level — 44 of them

| requirement | status | what it asks for |
|---|---|---|
| SBD-AC-05 | **needs attention** (secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment, secrets.credential-assignment) | Secrets are stored in a secret manager; keys/certs rotate automatically; no secrets in code/logs. |
| C11.1.1 | not verified | Verify that the model has undergone alignment and safety training or fine-tuning to prevent the model from generating disallowed content categories. |
| C11.1.2 | not verified | Verify that a version-controlled alignment test suite is run on every model update or release. |
| C11.1.3 | not verified | Verify that models are evaluated against known adversarial attack techniques relevant to their modality. |
| C11.2.1 | not verified | Verify that model-inferred sensitive attributes are not directly returned in outputs. |
| C11.2.2 | not verified | Verify that inference endpoints enforce per-principal and global rate limits sized to the extraction threat model, and not solely as a generic API throttle. |
| C11.3.1 | not verified | Verify that query-pattern analysis feeds an extraction-attempt detector. |
| C12.1.1 | not verified | Verify that AI interactions are logged with session context and AI-specific telemetry. |
| C12.2.1 | not verified | Verify that the system detects and alerts on known jailbreak patterns, prompt injection attempts, and adversarial inputs. |
| C2.1.1 | not verified | Verify that input normalization is applied before tokenization or embedding. |
| C2.1.2 | not verified | Verify that encoding and representation smuggling in inputs is detected and mitigated. Approved mitigations include canonicalization, strict schema validation, policy-based rejection, or explicit marking. |
| C2.1.3 | not verified | Verify that all inputs that could steer model behavior are treated as untrusted and screened by a prompt injection detection ruleset or classifier, with flagged inputs blocked. |
| C2.1.4 | not verified | Verify that input length controls prevent content from exceeding the context window. The controls must reject inputs that exceed token limits rather than truncating them. |
| C2.1.5 | not verified | Verify that the system implements a character set restriction for all inputs. The restriction must use an allow-list approach that permits only characters that are explicitly required. |
| C3.1.1 | not verified | Verify that a model registry maintains an inventory of all deployed model artifacts and their origin. |
| C3.2.1 | not verified | Verify that models undergo automated input validation testing, safety evaluation testing, and output sanitization testing before deployment. |
| C6.1.2 | not verified | Verify that model weights, datasets, and fine-tuning adapters are downloaded only from approved sources. |
| C6.2.1 | not verified | Verify that every model artifact publishes a version-controlled, machine-readable AI BOM listing datasets, weights, licenses, and data-origin statements. |
| C7.1.1 | not verified | Verify that the application validates all model outputs against a defined schema and rejects any output that does not match. |
| C7.1.2 | not verified | Verify that model-generated output is bounded by length limits and termination controls. |
| C7.4.1 | not verified | Verify that responses generated using retrieval-augmented generation (RAG) include attribution to the source documents. |
| C7.4.2 | not verified | Verify that RAG attributions are derived from retrieval metadata and are not generated by the model, so provenance cannot be fabricated. |
| C9.1.1 | not verified | Verify that per-tool quotas and timeouts (e.g., CPU, memory, disk, egress, and execution time) are enforced. |
| C9.1.2 | not verified | Verify that per-execution budgets (e.g., max recursion depth, token use, and monetary spend) are configured and enforced by the runtime. |
| C9.2.1 | not verified | Verify that the agent runtime blocks execution of privileged, high-impact, or irreversible actions until explicit human approval is received and verified. |
| C9.3.1 | not verified | Verify that each tool/plugin executes in a least-privilege sandbox or is otherwise isolated from model operations. |
| C9.3.2 | not verified | Verify that tool outputs are validated against schemas. |
| C9.6.1 | not verified | Verify that a manual kill-switch mechanism exists to immediately halt AI model inference and outputs. |
| SBD-AC-01 | not verified | All communications use TLS/mTLS; service identity is verified (e.g., mesh-issued certs). |
| SBD-AC-02 | not verified | Central IdP (OIDC/OAuth2) is used; MFA enforced on privileged/admin paths; tokens are short-lived. |
| SBD-AC-03 | not verified | RBAC/ABAC governs APIs and publish/consume on messaging; least privilege is applied. |
| SBD-AC-06 | not verified | Applicable regulatory controls (e.g., privacy/financial) are identified with evidence of design alignment. |
| SBD-AC-07 | not verified | Least privilege extends to CI/CD, VCS apps, chat-ops, and third-party tooling; periodic reviews are scheduled. |
| SBD-DM-02 | not verified | Encryption in transit (TLS/mTLS) and at rest with managed keys and rotation is designed in. |
| SBD-MT-02 | not verified | Metrics/SLOs and dashboards cover service health and event-flow anomalies; alerts are actionable. |
| SBD-MT-03 | not verified | ASVS-aligned security tests and negative tests from threat-modeling are planned in the test strategy. |
| SBD-MT-04 | not verified | SbD controls are verifiable in test (isolation, mTLS, authZ denials, rate-limit behavior). |
| SBD-MT-05 | not verified | OpenAPI/AsyncAPI and event catalogs are published; ADRs/runbooks are current. |
| SBD-MT-06 | not verified | A documented Incident Response plan (roles, comms, evidence handling) exists and is rehearsed. |
| SBD-MT-07 | not verified | Audit log retention ≥12 months with tamper-evidence and a searchable hot window is defined. |
| SBD-RR-06 | not verified | Timeouts on all calls; health probes; explicit failover/multi-AZ strategies for critical paths. |
| SBD-RR-08 | not verified | Caching/CDN/back-pressure patterns are applied where appropriate; performance guardrails are defined. |
| AC.12.1 | checked (config.workflow-runs-fork-code: 2 GitHub Actions workflow files in .github/workflows, none started by `pull_request_target` or `workflow_run`; a setting that sends secrets to pull requests from forks is not in any file) | Verify that workflows triggered by untrusted contributions (GitHub Actions `pull_request_target`, `workflow_run`, and equivalent fork-aware triggers in other CI systems) never check out, build, test, or otherwise execute untrusted code in a context that has repository write permissions or access to repository, organization, package-registry, cloud, or deployment secrets. Where a privileged follow-up step is needed, the untrusted contribution is first processed in an unprivileged `pull_request` workflow, and only validated passive artifacts are passed forward to a separate privileged workflow. |
| AC.12.2 | checked (config.workflow-checkout-keeps-token: 2 GitHub Actions workflow files in .github/workflows: every checkout sets `persist-credentials: false`; credentials kept on the runner some other way are not in any file) | Verify that secrets, credentials, and pipeline job tokens are not persisted into workspaces that process AI-touched or fork-originated untrusted code. For example, set `persist-credentials: false` on checkout where the platform supports it, and scrub CI runners of cached credentials before AI tooling runs. |

## How the app is built with AI (OWASP AISVS Appendix C)

19 requirements of OWASP AISVS Appendix C (AI-Assisted Secure Coding) apply to how this app is built with an AI coding tool, rather than to the app itself, and nothing has checked them. They are listed here rather than in the counts above. 13 are what the rules given to your AI coding tool come from (`sv rules`, or `securevibe_guidance` from inside the tool); the rules are instructions, and following them is not evidence that they are met. 1 is your decision, and is among your questions. Nothing in `sv` reaches the other 5: most are about a CI pipeline or an organization's AI tooling. 1 more does not apply to this app, and is listed with the others that do not.

| requirement | what happens to it | what it asks for |
|---|---|---|
| AC.1.1 | nothing in `sv` reaches it | Verify that a written workflow says when AI tools may generate, refactor, or review code. The workflow names the approved tools, the prohibited use cases, and the data classifications that are allowed as input. |
| AC.2.1 | nothing in `sv` reaches it | Verify that every AI tool, whether it is an assistant, a reviewer, an agent, or an MCP server, has a threat model. The threat model covers misuse, model inversion, training-data leakage, prompt injection from untrusted input, insecure output handling, excessive agency, and risk inherited from its dependency chain. |
| AC.3.1 | given to your AI coding tool as a rule | Verify that written guidance forbids putting secrets, credentials, PII, or classified data in any prompt sent to an AI tool. The guidance is enforced in pre-commit hooks, IDE integrations, and CI. |
| AC.3.2 | given to your AI coding tool as a rule | Verify that technical controls automatically strip sensitive material from any context window sent to an AI tool. Client-side redaction, approved context filters, and secret scanners with pre-prompt hooks all qualify. |
| AC.3.3 | given to your AI coding tool as a rule | Verify that any externally sourced context being fed to an AI tool is treated as untrusted and screened for prompt injection before it reaches the prompt. Sources to cover: PR descriptions and comments, fork-supplied diffs, issue bodies, commit messages, third-party documentation, web search results, and MCP tool outputs. |
| AC.3.4 | given to your AI coding tool as a rule | Verify that the AI tool enforces an instruction hierarchy, with system and developer messages taking precedence over untrusted repository content. This hierarchy has to hold across multi-turn conversations and tool-augmented workflows. |
| AC.4.1 | your decision, among your questions | Verify that AI-generated code always goes through code review by a qualified human engineer. The reviewer must not be the same identity that asked for the AI generation in the first place (separation of duties). And the AI agent itself does not count as the human reviewer. |
| AC.5.1 | nothing in `sv` reaches it | Verify that prompt-and-response pairs are logged with stable correlation identifiers, so that an investigator can later replay the whole chain: prompt → response → commit → build → deployment. |
| AC.7.1 | given to your AI coding tool as a rule | Verify that AI-generated or AI-modified artifacts are clearly labeled and tracked as such. Artifact classes in scope include infrastructure-as-code (Terraform, CloudFormation, Pulumi, Bicep), CI/CD workflow files (GitHub Actions, GitLab CI, Jenkinsfile, Argo Workflows, Tekton), container and orchestration manifests (Dockerfile, Kubernetes, Helm), and security policy artifacts (IAM, OPA/Rego, NetworkPolicy, admission controllers). |
| AC.8.1 | given to your AI coding tool as a rule | Verify that autonomous agents cannot approve, merge, sign, or deploy artifacts that they themselves generated, and that this constraint is enforced by the source-control system, the CI system, and the artifact registry. Policy alone does not satisfy this control. |
| AC.10.1 | given to your AI coding tool as a rule | Verify that AI-generated artifacts carry the required origin and generation fields: model identity and version, tool or agent identity, generation context, prompt hash, human involvement, session identifiers, and correlation IDs. |
| AC.11.1 | given to your AI coding tool as a rule | Verify that AI review and assistant bots treat every piece of PR-supplied content (diff, title, description, comments, file contents, commit messages, linked external URLs) as untrusted input, and apply the AISVS C2.1 prompt-injection defenses: instruction-hierarchy enforcement, content sanitization, and indirect-injection detection. |
| AC.11.2 | given to your AI coding tool as a rule | Verify that AI review and assistant bot system prompts and policy configurations are integrity-checked at load time (signed, hash-pinned), and that nothing in the repository, in branch contents, in PR-sourced environment variables, or in any other user-controllable input can modify them. |
| AC.11.3 | given to your AI coding tool as a rule | Verify that AI review and assistant bots emit only structured, schema-validated output (JSON with an allow-list of fields and actions). Any free-form output is treated as untrusted and never executed as a command, a query, a shell snippet, or a workflow step. |
| AC.12.3 | given to your AI coding tool as a rule | Verify that secrets are not exposed to workflows running code from forks or first-time contributors. Environment-protection rules (or the platform equivalent, such as protected variables and deployment approvals) require a manual approval before any secret-bearing job runs for those contributions. This control pairs with AC.11.7 and AC.13.2. Bot-level enforcement under AC.11.7 does not substitute for the platform-level enforcement required here. |
| AC.13.1 | nothing in `sv` reaches it | Verify that contribution-velocity and contributor-reputation analytics flag anomalies: bulk PR creation from newly created accounts, coordinated fork waves immediately preceding PRs, PR volumes that are inconsistent with human authorship, and reuse of payload patterns across unrelated repositories. |
| AC.13.2 | nothing in `sv` reaches it | Verify that PRs from first-time or low-reputation contributors require maintainer approval before any privileged workflow processes them. Privileged workflows here include AI review bots, secret-bearing jobs, and external-integration calls. |
| AC.14.1 | given to your AI coding tool as a rule | Verify that an incident-response playbook exists for AI-in-pipeline compromise. At minimum it covers: revoking AI-agent credentials, rotating every secret that touched the compromised workflow run, quarantining the compromised artifacts, notifying downstream consumers, notifying regulators where applicable, and preserving prompts, responses, and audit logs for forensics. |
| AC.14.2 | given to your AI coding tool as a rule | Verify that any secret that touched a workflow run associated with a suspicious PR, a prompt-injection event, or an AI-agent anomaly is automatically rotated, and that downstream issuers (cloud IAM, package registries, signing-key custodians) are notified of the rotation. |

## Threats

What could go wrong with an app like this one, by the part of it each threat concerns, and what the checks showed about each. These are the threats sv has rules for, for what was found in this app: not every threat there is. None is called handled. A threat is only as settled as the requirements that answer it, and each of those is one automated check at most, so the best a threat can be here is checked in part. Found threats come first, then those nothing has looked at.

Parts of the app: Browsers and the app; The app itself; The app's stored data; The AI model; Uploaded files; Outside services; Live connections (WebSockets).

24 threats: 2 found, 20 not verified, 2 checked in part, 0 cannot place.

| threat | status | part of the app | what could happen | the requirements that answer it |
|---|---|---|---|---|
| T-13 (changing what should not change) | found | Uploaded files | A harmful file, such as a script disguised as an image or an SVG with code in it, is uploaded and later opened by someone else. | needs attention: V5.3.2; not verified: V5.2.2, V5.3.1; not among this app's requirements at its level: V5.4.1, V5.4.2 |
| T-40 (exposing information) | found | Live connections (WebSockets) | Messages on a live connection are read on the network. | needs attention: V4.4.1 |
| T-01 (pretending to be someone else) | not verified | Browsers and the app | Someone signs in as another person by guessing a password, reusing a leaked one, or stealing a session cookie. | not verified: V6.2.1, V6.2.4, V6.3.1, V7.2.3; not among this app's requirements at its level: V3.3.4 |
| T-02 (gaining more access than allowed) | not verified | Browsers and the app | A signed-in person opens administrator pages or other people's records by changing a web address. | not verified: V8.2.1, V8.3.1, V8.2.2, V15.3.1; not among this app's requirements at its level: V8.2.3 |
| T-03 (denying having done something) | not verified | Browsers and the app | Someone denies having signed in or changed something, and there is no reliable record of it. | not among this app's requirements at its level: V16.3.1, V16.3.2, V16.4.2 |
| T-05 (exposing information) | not verified | Browsers and the app | Traffic is read on the network, or pages, caches, and error messages reveal what they should not. | not verified: V14.3.1; not among this app's requirements at its level: V16.5.1, V14.3.2, V12.1.1, V3.4.1, V3.3.1 |
| T-06 (making the app unavailable) | not verified | Browsers and the app | Floods of requests, slow connections, or huge request bodies make the app unavailable. | not among this app's requirements at its level: V2.4.1, V15.2.2 |
| T-28 (exposing information) | not verified | The app itself | Secrets (session keys, encryption keys, API keys) leak through the code, the logs, or error pages. | not verified: V13.4.1; not among this app's requirements at its level: V13.3.1, V16.2.5, V16.5.1 |
| T-29 (denying having done something) | not verified | The app itself | Log entries are altered or deleted to hide what happened. | not among this app's requirements at its level: V16.4.2, V16.4.1 |
| T-25 (exposing information) | not verified | The app's stored data | Someone with access to the computer, or to a backup, copies the stored data and reads it. | not among this app's requirements at its level: V11.4.2, V14.2.4 |
| T-26 (changing what should not change) | not verified | The app's stored data | A form submitted twice, or two people editing at once, corrupts or duplicates a record. | not among this app's requirements at its level: V2.3.3 |
| T-07 (changing what should not change) | not verified | The AI model | Text typed by a person, or hidden inside a record, tricks the model into ignoring its instructions (prompt injection). | not verified: C2.1.3, C12.2.1, C2.1.1, C2.1.5; not among this app's requirements at its level: C2.1.6, C2.1.7 |
| T-08 (exposing information) | not verified | The AI model | The model reveals other people's records, or its own instructions. | not among this app's requirements at its level: C5.2.1, C9.5.3, C7.3.2, C5.2.4 |
| T-09 (making the app unavailable) | not verified | The AI model | Runaway or abusive use of the model runs up the AI bill, spends tokens without limit, or exhausts the provider's quota. | not verified: C9.1.2, C9.6.1, C11.2.2; not among this app's requirements at its level: C12.2.5, C12.4.3 |
| T-10 (pretending to be someone else) | not verified | The AI model | The AI provider's API key leaks, in logs, in a prompt, or in generated text, and someone else uses it. | not among this app's requirements at its level: C9.5.4, V13.3.1, V13.3.2, V16.2.5 |
| T-11 (gaining more access than allowed) | not verified | The AI model | The model makes a change the person did not intend, or one they are not allowed to make. | not verified: C9.2.1; not among this app's requirements at its level: C9.5.1 |
| T-14 (making the app unavailable) | not verified | Uploaded files | Oversized or endless uploads fill the disk. | not verified: V5.2.1; not among this app's requirements at its level: V2.3.2 |
| T-15 (exposing information) | not verified | Uploaded files | Someone downloads another person's file by guessing its address. | not verified: V8.2.2 |
| T-22 (exposing information) | not verified | Outside services | Data sent to an outside service is exposed if that service is breached or the connection is intercepted. | not among this app's requirements at its level: V12.3.2, V13.1.1 |
| T-23 (making the app unavailable) | not verified | Outside services | An outside service is slow or down and takes the app down with it. | not among this app's requirements at its level: V16.5.2 |
| T-24 (changing what should not change) | not verified | Outside services | The app is tricked into calling a different address than the service it means to (server-side request forgery). | not among this app's requirements at its level: V1.3.6, V13.2.4, V15.3.2 |
| T-39 (changing what should not change) | not verified | Live connections (WebSockets) | Another website opens a live connection to the app with the person's cookies and sends messages as them. | not among this app's requirements at its level: V4.4.2, V4.4.4 |
| T-04 (changing what should not change) | checked in part | Browsers and the app | Crafted input (injection, a request forged from another site, oversized or unexpected fields) changes data or behavior. | checked: V1.2.4; not verified: V2.2.1, V2.2.2, V1.2.1, V3.5.1; not among this app's requirements at its level: V15.3.3, V3.4.3, V15.3.6 |
| T-27 (changing what should not change) | checked in part | The app itself | A package the app depends on has a known vulnerability or a malicious update. | checked: V15.2.1; not among this app's requirements at its level: V15.1.2 |

### For a security reviewer: these threats in MITRE ATLAS

The threats above that are about AI, as MITRE ATLAS names them (release 2026.09), for anyone who works from that catalog. These are references, not checks: nothing was tested against ATLAS, and they change no status above. MITRE ATLAS is a trademark of The MITRE Corporation; its data is used under the Apache License 2.0.

| threat | MITRE ATLAS technique | what the two share |
|---|---|---|
| T-07 | AML.T0051 LLM Prompt Injection | prompt injection |
| T-08 | AML.T0057 LLM Data Leakage | data leakage of other people's records |
| T-08 | AML.T0056 Extract LLM System Prompt | revealing its own instructions, the system prompt |
| T-09 | AML.T0034 Cost Harvesting | running up the bill: the cost, harvesting it |
| T-09 | AML.T0029 Denial of AI Service | exhausting the provider's quota, a denial of the service |
| T-10 | AML.T0055 Unsecured Credentials | a leaked API key is an unsecured credential |
| T-11 | AML.T0053 AI Agent Tool Invocation | the model makes a change through an agent tool invocation |

## What only you can check

13 of the requirements that apply cannot be settled by any tool: they ask what your rules are, how the app is built, or what is true of it in production. Each one below says what doing something about it involves. None of them is counted as met — doing the thing is what would change that, not reading it here.

A further 36 are the Secure by Design and AISVS design-review controls, which are not listed one by one: those standards are checklists already, and repeating them here would be another wall of text. They are in the table above, and in the standards themselves.

| requirement | what to do | how |
|---|---|---|
| V2.1.1 — What counts as valid input | write your answer in security-notes.md (`sv notes` makes it) | For each kind of information people type into the app (names, email addresses, dates, amounts, free text), write down the validation rules: what a valid value looks like, how long it may be, and what the app does with one that is not valid. **Where to look:** Go through every form and every field an API accepts, and for each one write what a good value looks like. The quickest way to find them all is to open each page that has a form and list its inputs. |
| V6.1.1 — How sign-in is protected against guessing | write your answer in security-notes.md (`sv notes` makes it) | How the app defends against someone trying many passwords (password brute force) or leaked email and password pairs (credential stuffing): rate limiting, delays, or lockout, and the numbers, such as five failed attempts in fifteen minutes. Say how these controls are configured, and how the app stops an attacker locking a real person out on purpose (malicious account lockout). **Where to look:** Look in your sign-in code for anything that counts failures — a rate limiter, a lockout, a delay. If you find nothing, that is the answer, and the number to write down is the one you want rather than the one you have. |
| V8.1.1 — Who may do what | write your answer in security-notes.md (`sv notes` makes it) | The authorization rules: which kinds of users may use which functions (function-level: only administrators may open the admin page), and which records each may see or change (data-specific: a person may only open their own notes). **Where to look:** List the kinds of user the app has, then walk through the app as each one and note what they can reach. The pages that only some people should see, and the records that belong to one person, are what these rules are about. |
| V15.1.1 — How quickly outdated libraries are updated | write your answer in security-notes.md (`sv notes` makes it) | Time frames for remediation: how soon a third-party library with a known vulnerability is updated, by how serious the vulnerability is (for example, critical within a week), and how often libraries are updated in general. **Where to look:** Decide the number of days you would accept between a vulnerability being published and it being fixed, for each level of severity. Start from how bad it would be for this app rather than from what other people write down. Then put the same numbers in securevibe.toml as `[policy] fix-within-days`, so `sv audit` can hold the app's packages to them. |
| V2.2.2 — Input validation is enforced at a trusted service layer | answer it in the [design] section of securevibe.toml | Does the application enforce input validation on the server — a trusted service layer — and not only in the browser? Client-side validation improves usability and should be kept, but anyone can skip it by sending a request straight to the server, so it settles nothing on its own. **Where to look:** Find where the app receives a form or an API request, and look at what happens to the values before they are used. If the only checks you find are in the browser — HTML attributes, JavaScript — that is the answer. |
| V8.3.1 — Authorization rules are enforced at a trusted service layer | answer it in the [design] section of securevibe.toml | Does the application enforce its authorization rules at a trusted service layer — the server — rather than relying on controls an untrusted consumer could manipulate, such as a hidden button or a disabled field in the browser? Hiding a link is not a rule: anyone can request the address directly. **Where to look:** Take a page or an action only some people should reach, and find the code that stops everybody else. If the only thing you find is the button being hidden in the template, that is the answer. |
| V15.3.1 — Only the fields that are needed are sent back | answer it in the [design] section of securevibe.toml | When the application returns a record, does it return only the required fields, rather than the whole object with fields the person should not see? **Where to look:** Look at what an API returns for one record, or what a page sends to the browser, and compare it with what is shown. Anything extra in the response is being sent and simply not displayed. |
| V2.3.1 — Steps cannot be skipped or done out of order | check it by hand; nothing here can | Take a flow with more than one step — checkout, sign-up with a confirmation, anything with a "next" button. Write down the address of the last step. Start the flow again, and go straight to that address without doing the steps before it. It should refuse. Then try the steps in the wrong order, and try the same step twice. Describing the flow in securevibe.toml as `flow` under [stack.run.users] lets `sv report --run` try the first two skips for you; the wrong order and the repeated step are still yours. |
| C11.1.1 — The AI model has had safety training | check it by hand; nothing here can | Look up which model the app uses (your AI coding tool can tell you where it is named) and open the provider's model card or safety documentation. Check that it describes alignment or safety training against disallowed content. Models from the major providers do; a model you downloaded or trained yourself may not, and then this is yours to arrange. |
| C11.1.2 — The AI's safety is tested again whenever the model changes | check it by hand; nothing here can | Write down a short list of prompts the app must refuse or answer carefully, and keep it in version control beside the code. Each time the model is updated or its version changes, run the list again and compare the answers. Check whether this happens today; if nobody reruns anything when the model changes, the answer is no. |
| C11.1.3 — The AI has been tried against known attacks | check it by hand; nothing here can | Try the well-known attacks on the AI part of your app yourself: ask it to ignore its instructions, to reveal its system prompt, to role-play its way past a rule, or hide an instruction inside a document or image it reads. Write down which ones it resisted. A tool such as garak runs many of these adversarial techniques at once. |
| C11.3.1 — Someone copying the AI by asking it everything would be noticed | check it by hand; nothing here can | Look at what the app records about the questions people ask the AI: who asked, how many, how fast. Check whether anything watches that record for the pattern of someone systematically asking thousands of varied questions to copy what the model knows, the query pattern of an extraction attempt, and warns somebody. |
| AC.4.1 — A person reviews the code the AI wrote | check it by hand; nothing here can | Look at how changes to the app get in: check that every change your AI coding tool wrote is read and approved by a qualified person before it goes live, and that the reviewer is not the same person who asked the AI for the code. The AI agent does not count as the human reviewer. If changes go straight from the AI to the live app, the answer is no. |

## Tests worth writing first

Nothing produced evidence about these, and no test in the app names them. A test that names a requirement's id and passes is the one way to give evidence about any requirement, including the ones no check here can reach. These are the level 1 ones. Name only what a test really checks: nothing here can tell whether it does.

47 more have no evidence and are not listed at all, because an application's own tests cannot show them: they ask for documentation, a deployment setting, a development process, or a design decision, and a person answers them.

Named in a test and still without evidence, because the tests were not run here or did not pass: V15.3.1, V2.2.2.

| requirement | what it asks for |
|---|---|
| V1.2.1 | Verify that output encoding for an HTTP response, HTML document, or XML document is relevant for the context required, such as encoding the relevant characters for HTML elements, HTML attributes, HTML comments, CSS, or HTTP header fields, to avoid changing the message or document structure. |
| V1.2.2 | Verify that when dynamically building URLs, untrusted data is encoded according to its context (e.g., URL encoding or base64url encoding for query or path parameters). Ensure that only safe URL protocols are permitted (e.g., disallow javascript: or data:). |
| V1.2.3 | Verify that output encoding or escaping is used when dynamically building JavaScript content (including JSON), to avoid changing the message or document structure (to avoid JavaScript and JSON injection). |
| V1.3.1 | Verify that all untrusted HTML input from WYSIWYG editors or similar is sanitized using a well-known and secure HTML sanitization library or framework feature. |
| V2.2.1 | Verify that input is validated to enforce business or functional expectations for that input. This should either use positive validation against an allow list of values, patterns, and ranges, or be based on comparing the input to an expected structure and logical limits according to predefined rules. For L1, this can focus on input which is used to make specific business or security decisions. For L2 and up, this should apply to all input. |
| V3.2.1 | Verify that security controls are in place to prevent browsers from rendering content or functionality in HTTP responses in an incorrect context (e.g., when an API, a user-uploaded file or other resource is requested directly). Possible controls could include: not serving the content unless HTTP request header fields (such as Sec-Fetch-\\*) indicate it is the correct context, using the sandbox directive of the Content-Security-Policy header field or using the attachment disposition type in the Content-Disposition header field. |
| V3.2.2 | Verify that content intended to be displayed as text, rather than rendered as HTML, is handled using safe rendering functions (such as createTextNode or textContent) to prevent unintended execution of content such as HTML or JavaScript. |
| V3.4.2 | Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header field is a fixed value by the application, or if the Origin HTTP request header field value is used, it is validated against an allowlist of trusted origins. When 'Access-Control-Allow-Origin: *' needs to be used, verify that the response does not include any sensitive information. |
| V3.5.1 | Verify that, if the application does not rely on the CORS preflight mechanism to prevent disallowed cross-origin requests to use sensitive functionality, these requests are validated to ensure they originate from the application itself. This may be done by using and validating anti-forgery tokens or requiring extra HTTP header fields that are not CORS-safelisted request-header fields. This is to defend against browser-based request forgery attacks, commonly known as cross-site request forgery (CSRF). |
| V3.5.2 | Verify that, if the application relies on the CORS preflight mechanism to prevent disallowed cross-origin use of sensitive functionality, it is not possible to call the functionality with a request which does not trigger a CORS-preflight request. This may require checking the values of the 'Origin' and 'Content-Type' request header fields or using an extra header field that is not a CORS-safelisted header-field. |
| V3.5.3 | Verify that HTTP requests to sensitive functionality use appropriate HTTP methods such as POST, PUT, PATCH, or DELETE, and not methods defined by the HTTP specification as "safe" such as HEAD, OPTIONS, or GET. Alternatively, strict validation of the Sec-Fetch-* request header fields can be used to ensure that the request did not originate from an inappropriate cross-origin call, a navigation request, or a resource load (such as an image source) where this is not expected. |
| V4.1.1 | Verify that every HTTP response with a message body contains a Content-Type header field that matches the actual content of the response, including the charset parameter to specify safe character encoding (e.g., UTF-8, ISO-8859-1) according to IANA Media Types, such as "text/", "/+xml" and "/xml". |
| V5.2.1 | Verify that the application will only accept files of a size which it can process without causing a loss of performance or a denial of service attack. |
| V5.2.2 | Verify that when the application accepts a file, either on its own or within an archive such as a zip file, it checks if the file extension matches an expected file extension and validates that the contents correspond to the type represented by the extension. This includes, but is not limited to, checking the initial 'magic bytes', performing image re-writing, and using specialized libraries for file content validation. For L1, this can focus just on files which are used to make specific business or security decisions. For L2 and up, this must apply to all files being accepted. |
| V5.3.1 | Verify that files uploaded or generated by untrusted input and stored in a public folder, are not executed as server-side program code when accessed directly with an HTTP request. |
| V6.2.1 | Verify that user set passwords are at least 8 characters in length although a minimum of 15 characters is strongly recommended. |
| V6.2.2 | Verify that users can change their password. |
| V6.2.3 | Verify that password change functionality requires the user's current and new password. |
| V6.2.4 | Verify that passwords submitted during account registration or password change are checked against an available set of, at least, the top 3000 passwords which match the application's password policy, e.g. minimum length. |
| V6.2.5 | Verify that passwords of any composition can be used, without rules limiting the type of characters permitted. There must be no requirement for a minimum number of upper or lower case characters, numbers, or special characters. |
| V6.2.6 | Verify that password input fields use type=password to mask the entry. Applications may allow the user to temporarily view the entire masked password, or the last typed character of the password. |
| V6.2.7 | Verify that "paste" functionality, browser password helpers, and external password managers are permitted. |
| V6.2.8 | Verify that the application verifies the user's password exactly as received from the user, without any modifications such as truncation or case transformation. |
| V6.3.2 | Verify that default user accounts (e.g., "root", "admin", or "sa") are not present in the application or are disabled. |
| V6.4.1 | Verify that system generated initial passwords or activation codes are securely randomly generated, follow the existing password policy, and expire after a short period of time or after they are initially used. These initial secrets must not be permitted to become the long term password. |
| V6.4.2 | Verify that password hints or knowledge-based authentication (so-called "secret questions") are not present. |
| V7.2.1 | Verify that the application performs all session token verification using a trusted, backend service. |
| V7.2.2 | Verify that the application uses either self-contained or reference tokens that are dynamically generated for session management, i.e. not using static API secrets and keys. |
| V7.2.3 | Verify that if reference tokens are used to represent user sessions, they are unique and generated using a cryptographically secure pseudo-random number generator (CSPRNG) and possess at least 128 bits of entropy. |
| V7.2.4 | Verify that the application generates a new session token on user authentication, including re-authentication, and terminates the current session token. |
| V7.4.1 | Verify that when session termination is triggered (such as logout or expiration), the application disallows any further use of the session. For reference tokens or stateful sessions, this means invalidating the session data at the application backend. Applications using self-contained tokens will need a solution such as maintaining a list of terminated tokens, disallowing tokens produced before a per-user date and time or rotating a per-user signing key. |
| V7.4.2 | Verify that the application terminates all active sessions when a user account is disabled or deleted (such as an employee leaving the company). |
| V8.2.1 | Verify that the application ensures that function-level access is restricted to consumers with explicit permissions. |
| V8.2.2 | Verify that the application ensures that data-specific access is restricted to consumers with explicit permissions to specific data items to mitigate insecure direct object reference (IDOR) and broken object level authorization (BOLA). |
| V13.4.1 | Verify that the application is deployed either without any source control metadata, including the .git or .svn folders, or in a way that these folders are inaccessible both externally and to the application itself. |
| V14.2.1 | Verify that sensitive data is only sent to the server in the HTTP message body or header fields, and that the URL and query string do not contain sensitive information, such as an API key or session token. |
| V14.3.1 | Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. The 'Clear-Site-Data' HTTP response header field may be able to help with this but the client-side should also be able to clear up if the server connection is not available when the session is terminated. |
| C2.1.1 | Verify that input normalization is applied before tokenization or embedding. |
| C2.1.2 | Verify that encoding and representation smuggling in inputs is detected and mitigated. Approved mitigations include canonicalization, strict schema validation, policy-based rejection, or explicit marking. |
| C2.1.3 | Verify that all inputs that could steer model behavior are treated as untrusted and screened by a prompt injection detection ruleset or classifier, with flagged inputs blocked. |
| C2.1.4 | Verify that input length controls prevent content from exceeding the context window. The controls must reject inputs that exceed token limits rather than truncating them. |
| C2.1.5 | Verify that the system implements a character set restriction for all inputs. The restriction must use an allow-list approach that permits only characters that are explicitly required. |
| C3.2.1 | Verify that models undergo automated input validation testing, safety evaluation testing, and output sanitization testing before deployment. |
| C7.1.1 | Verify that the application validates all model outputs against a defined schema and rejects any output that does not match. |
| C7.1.2 | Verify that model-generated output is bounded by length limits and termination controls. |
| C7.4.1 | Verify that responses generated using retrieval-augmented generation (RAG) include attribution to the source documents. |
| C7.4.2 | Verify that RAG attributions are derived from retrieval metadata and are not generated by the model, so provenance cannot be fabricated. |
| C9.1.1 | Verify that per-tool quotas and timeouts (e.g., CPU, memory, disk, egress, and execution time) are enforced. |
| C9.1.2 | Verify that per-execution budgets (e.g., max recursion depth, token use, and monetary spend) are configured and enforced by the runtime. |
| C9.2.1 | Verify that the agent runtime blocks execution of privileged, high-impact, or irreversible actions until explicit human approval is received and verified. |
| C9.3.1 | Verify that each tool/plugin executes in a least-privilege sandbox or is otherwise isolated from model operations. |
| C9.3.2 | Verify that tool outputs are validated against schemas. |
| C9.6.1 | Verify that a manual kill-switch mechanism exists to immediately halt AI model inference and outputs. |
| C11.2.1 | Verify that model-inferred sensitive attributes are not directly returned in outputs. |
| C11.2.2 | Verify that inference endpoints enforce per-principal and global rate limits sized to the extraction threat model, and not solely as a generic API throttle. |
| C12.1.1 | Verify that AI interactions are logged with session context and AI-specific telemetry. |
| C12.2.1 | Verify that the system detects and alerts on known jailbreak patterns, prompt injection attempts, and adversarial inputs. |


</details>

## Findings about requirements this app is not being assessed against

Something was found, and it named a requirement that is not in the list above. That is worth a look either way: either the requirement was excluded when it should not have been, or the check is citing a requirement that has nothing to do with it.

| found by | about | where that requirement ended up |
|---|---|---|
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.javascript.lang.security.detect-insecure-websocket.detect-insecure-websocket | V12.3.1 | above this app's target level |
| semgrep.typescript.react.security.react-insecure-request.react-insecure-request | V12.3.1 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.2.3 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |
| secrets.credential-assignment | V13.3.1 | above this app's target level |

## Checks that ran and found nothing, against nothing in the tables above

These were satisfied. They appear here rather than beside a requirement because what they look at is not something this app is being assessed on.

| check | what it covered | why it is here |
|---|---|---|
| config.gitignore-covers-env | the files this check reads | V13.3.1 — above this app's target level |
| config.security-contact | the files this check reads | it names no requirement in any loaded framework |
| config.versions-pinned | the files this check reads | V15.1.2 — above this app's target level |
| config.workflow-secrets-with-fork-code | 2 GitHub Actions workflow files in .github/workflows; whether a person must approve a job before it gets secrets is a repository setting | it names no requirement in any loaded framework |
| ast.unsafe-deserialization | data read with a reader that can build any kind of object, such as pickle, Marshal, or PHP's unserialize, in 3 javascript files | V1.5.2 — above this app's target level |
| ast.open-redirect | a redirect to a destination built from a value, in 3 javascript files and 53 rust files | V3.7.2 — above this app's target level |

## Secure by Design controls above this app's target level

The checklist has no levels of its own. Each control takes the level of the ASVS requirement that asks the same thing, or is shown at every level when none does; a few keep the level `sv` derived from the checklist's severity, which is lower. These are the ones that came out above this app's target.

| control | where its level came from | what it asks for |
|---|---|---|
| SBD-AS-07 | level 2, as V16.5.2 | Startup resilience: services handle missing dependencies; autoscaling defined with minimum replicas. |
| SBD-DM-01 | level 2, as V14.1.1 | Data are classified with named owners; controls are proportional to classification. |
| SBD-DM-04 | level 2, as V2.3.3 | Cross-service transactions use Sagas/compensations; 2PC is avoided; prefer intra-service ACID first. |
| SBD-DM-05 | level 2, as V14.1.2 | Retention/deletion policies exist per data class; minimization is applied to collection/storage. |
| SBD-MT-01 | level 2, as V16.1.1 | Structured centralized logs with correlation/trace IDs; administrative access is logged. |
| SBD-RR-01 | level 2, as V16.5.1 | Retries use exponential backoff + jitter; default exception handling and safe error models exist. |
| SBD-RR-02 | level 2, as V16.5.2 | Circuit breakers/bulkheads protect dependencies; non-critical features have fallback/degraded modes. |
| SBD-RR-05 | level 2, as V2.3.4 | All mutating endpoints enforce an Idempotency-Key; concurrency controls (locks/optimistic concurrency) are in place. |
| SBD-RR-07 | level 2, as V2.4.1 | Quotas and autoscaling are defined; rate-limits enforced at edges; minimum capacity documented. |

<details>
<summary><strong>Requirements that do not apply, and why</strong> — reference: why each was ruled out</summary>

An exclusion resting on the manifest's word is weaker than one resting on what the code actually contains. The last column says which this is.

| requirement | why not | rests on |
|---|---|---|
| AC.6.1 | This app does not fine-tune a model or run a feedback program that changes one. | claim (training) |
| C1.1.1 | This app does not train or fine-tune any AI model. It uses a ready-made model from a vendor, so training-data requirements do not apply. | claim (training) |
| C1.2.1 | This app does not train or fine-tune any AI model. It uses a ready-made model from a vendor, so training-data requirements do not apply. | claim (training) |
| C10.1.1 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.2.1 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.2.2 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.2.3 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.3.1 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.3.2 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.4.1 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.4.2 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C10.4.3 | The assistant does not use the Model Context Protocol (MCP) to connect to tools or servers. | claim (mcp) |
| C12.3.1 | Model drift is monitored by the vendor hosting the model, not by this app. | claim (self-hosted-model) |
| C12.5.1 | This app does not train models or manage training data. | claim (training) |
| C12.5.2 | This app does not train models or manage training data. | claim (training) |
| C2.2.1 | A separate content-moderation check (for violence, self-harm, hate and sexual content) is not turned on for this assistant. The vendor's model has its own built-in safety rules. It can be turned on later with the AI_MODERATION setting. | claim (ai-moderation) |
| C2.2.2 | A separate content-moderation check is not turned on for this assistant, so there is no classifier to test with other languages. | claim (ai-moderation) |
| C3.4.1 | This app does not build, deploy or roll back AI models of its own; it calls a model that its vendor hosts. | claim (self-hosted-model) |
| C4.1.1 | The AI model runs on its vendor's infrastructure, not on hardware this app controls. | claim (self-hosted-model) |
| C4.1.2 | The AI model runs on its vendor's infrastructure, not on hardware this app controls. | claim (self-hosted-model) |
| C4.3.1 | The AI model runs on its vendor's infrastructure, not on hardware this app controls. | claim (self-hosted-model) |
| C6.1.1 | No model files are downloaded or imported; the model stays with its vendor and is used over an API. | claim (self-hosted-model) |
| C7.3.1 | A separate content-moderation check on the assistant's answers is not turned on. The vendor's model has its own built-in safety rules. It can be turned on later with the AI_MODERATION setting. | claim (ai-moderation) |
| C8.1.1 | There is no vector database; conversation history is plain rows in the app's own database, scoped to each user. | claim (rag) |
| C8.2.1 | The assistant does not create embeddings or use a vector database. | claim (rag) |
| SBD-AC-04 | This app runs as one service, so there is no gateway or mesh to centralize authorization at. | claim (multiple-services) |
| SBD-AS-01 | This app runs as one service, so there are no trust zones between services to enforce and no cross-zone traffic to route through a gateway. | claim (multiple-services) |
| SBD-AS-02 | This app runs as one service, so there is nothing to discover and no addressing scheme to keep consistent. | claim (multiple-services) |
| SBD-AS-03 | This app runs as one service, so there are no boundaries between services to design and no traffic between them to protect. | claim (multiple-services) |
| SBD-AS-04 | This app runs as one service, so there are no synchronous chains between services to shorten. | claim (multiple-services) |
| SBD-AS-05 | This app runs as one service, so there are no contracts between services to version, and no consumers to notify. | claim (multiple-services) |
| SBD-AS-06 | This app runs as one service and has no background job queue, so there is no messaging to make durable. | claim (multiple-services) |
| SBD-AS-08 | This app runs as one service, so there is no integration boundary to put an anti-corruption layer behind. | claim (multiple-services) |
| SBD-DM-03 | This app runs as one service, takes no payments and runs no background jobs, so nothing delivers the same message, webhook or job to it twice. | claim (multiple-services) |
| SBD-DM-06 | This app runs as one service, so there is one copy of the data and no consistency model between services to document. | claim (multiple-services) |
| SBD-RR-03 | This app runs as one service and has no background job queue, so there is no asynchronous messaging whose semantics need defining. | claim (multiple-services) |
| SBD-RR-04 | This app runs as one service, so there is no shared gateway or bus between services to keep available. | claim (multiple-services) |
| V1.5.1 | No XML parser is used, so XML external entity (XXE) attacks are not possible. | derived (xml) |
| V10.4.1 | This app does not run an OAuth authorization server: the service that signs people in and issues tokens on behalf of other applications. These rules are for whoever runs one. Signing in through somebody else's, such as Google or Microsoft, does not make this app one. | claim (authorization-server) |
| V10.4.2 | This app does not run an OAuth authorization server: the service that signs people in and issues tokens on behalf of other applications. These rules are for whoever runs one. Signing in through somebody else's, such as Google or Microsoft, does not make this app one. | claim (authorization-server) |
| V10.4.3 | This app does not run an OAuth authorization server: the service that signs people in and issues tokens on behalf of other applications. These rules are for whoever runs one. Signing in through somebody else's, such as Google or Microsoft, does not make this app one. | claim (authorization-server) |
| V10.4.4 | This app does not run an OAuth authorization server: the service that signs people in and issues tokens on behalf of other applications. These rules are for whoever runs one. Signing in through somebody else's, such as Google or Microsoft, does not make this app one. | claim (authorization-server) |
| V10.4.5 | This app does not run an OAuth authorization server: the service that signs people in and issues tokens on behalf of other applications. These rules are for whoever runs one. Signing in through somebody else's, such as Google or Microsoft, does not make this app one. | claim (authorization-server) |
| V12.1.1 | This app runs on this computer only (loopback address) without HTTPS, so there is no TLS connection to configure. | claim (tls) |
| V12.2.1 | This app is not reachable from outside this computer and has no HTTPS yet, so there is no public connection to encrypt. | claim (tls) |
| V12.2.2 | This app is not reachable from outside this computer and has no HTTPS yet, so there is no public connection to encrypt. | claim (tls) |
| V3.3.1 | This app runs on this computer only (loopback address, no HTTPS), so the 'Secure' cookie flag has no effect yet. | claim (tls) |
| V3.4.1 | HTTP Strict Transport Security (HSTS) tells browsers to insist on HTTPS. This app runs on this computer only without HTTPS, so the header would have no effect. | claim (tls) |
| V9.1.1 | This app does not issue self-contained tokens such as JWTs. Its API keys are opaque values that are checked against the database on every request. | claim (jwt) |
| V9.1.2 | This app does not issue self-contained tokens such as JWTs. Its API keys are opaque values that are checked against the database on every request. | claim (jwt) |
| V9.1.3 | This app does not issue self-contained tokens such as JWTs. Its API keys are opaque values that are checked against the database on every request. | claim (jwt) |
| V9.2.1 | This app does not issue self-contained tokens such as JWTs. Its API keys are opaque values that are checked against the database on every request. | claim (jwt) |


</details>

## What the app says about itself

| about | securevibe.toml | the code | what that means |
|---|---|---|---|
| auth | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `argon2` appears in crates/sv-check/src/signed_in.rs. |
| oauth | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `openid` appears in crates/sv-run/assets/oidc-provider.mjs. |
| authorization-server | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| jwt | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| uploads | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `Multipart` appears in crates/sv-check/src/signed_in.rs. |
| payments | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| email | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| public-api | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| scheduler | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| multi-tenant | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| multiple-services | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| webrtc | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| external-apis | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `fetch(` appears in crates/sv-run/assets/browser-driver.mjs. |
| tls | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| internet | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `0.0.0.0` appears in crates/sv-check/src/live_tls.rs. |
| ai | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `openai` appears in crates/sv-run/assets/model-provider.mjs. |
| ai-actions | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `tool_calls` appears in crates/sv-run/assets/model-provider.mjs. |
| ai-history | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| ai-moderation | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| rag | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| web-search | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: `web_search` appears in crates/sv-manifest/src/lib.rs. |
| generates-media | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| mcp | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| training | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| level2 | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| self-hosted-model | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| multi-agent | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| multimodal-ai | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| out-of-band-auth | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| shared-hostname | no | nothing | Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as finding it absent. |
| ci-cd | yes | yes | The manifest and the code agree. |
| hosted-scm | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: .github is in the repository. |
| outside-contributors | no | yes | The code says otherwise, and the code wins: the requirements this would have switched off are switched on. What the code shows: CONTRIBUTING.md is in the repository. |
| iac | yes | yes | The manifest and the code agree. |
| websockets | nothing | yes | The manifest and the code agree. |
| graphql | nothing | no | The manifest and the code agree. |
| ldap | nothing | no | The manifest and the code agree. |
| xpath | nothing | no | The manifest and the code agree. |
| xml | nothing | no | The manifest and the code agree. |
| latex | nothing | no | The manifest and the code agree. |
| jndi | nothing | no | The manifest and the code agree. |
| memcache | nothing | no | The manifest and the code agree. |
| format-strings | nothing | no | The manifest and the code agree. |
| unmanaged-code | nothing | no | The manifest and the code agree. |
| postmessage | nothing | yes | The manifest and the code agree. |


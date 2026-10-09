```yaml
╭ [0]  ╭ Target: nmaguiar/gcutils:build (alpine 3.25.0_alpha20260805) 
│      ├ Class : os-pkgs 
│      ╰ Type  : alpine 
├ [1]  ╭ Target  : Java 
│      ├ Class   : lang-pkgs 
│      ├ Type    : jar 
│      ╰ Packages 
├ [2]  ╭ Target  : Node.js 
│      ├ Class   : lang-pkgs 
│      ├ Type    : node-pkg 
│      ╰ Packages 
├ [3]  ╭ Target         : Python 
│      ├ Class          : lang-pkgs 
│      ├ Type           : python-pkg 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-13346 
│                              ├ VendorIDs        ─ [0]: GHSA-qwm4-qh6w-59xr 
│                              ├ PkgName         : pip 
│                              ├ PkgPath         : usr/lib/python3.14/site-packages/pip-26.1.2.dist-info/METADATA 
│                              ├ PkgIdentifier    ╭ PURL: pkg:pypi/pip@26.1.2 
│                              │                  ╰ UID : 881d6693995189f8 
│                              ├ InstalledVersion: 26.1.2 
│                              ├ FixedVersion    : 26.2.0 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-13346 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory pip 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Apip 
│                              ├ Fingerprint     : sha256:b0c519f15f2e7156f535f391f936866837a4e5aea8dfeeed158ad
│                              │                   3e946c940cf 
│                              ├ Title           : pip: pip: Arbitrary file installation via malicious package
│                              │                   indexes 
│                              ├ Description     : pip would incorrectly handle doubly-encoded package URLs
│                              │                   from indexes allowing for files to be installed to arbitrary
│                              │                    locations on disk even when installing wheels.
│                              │                   
│                              │                   This vulnerability requires downloading or installing a
│                              │                   package from a malicious package index to succeed, malicious
│                              │                    packages alone are not able to exploit this vulnerability.
│                              │                   Note that this vulnerability only materially impacts users
│                              │                   running `pip download` with the `--only-binary` option as
│                              │                   installing source distributions from an untrusted index is
│                              │                   already an unsafe operation that executes code during
│                              │                   install time. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs           ─ [0]: CWE-36 
│                              ├ VendorSeverity   ╭ azure : 2 
│                              │                  ├ ghsa  : 2 
│                              │                  ├ nvd   : 2 
│                              │                  ├ photon: 2 
│                              │                  ╰ redhat: 2 
│                              ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/
│                              │                  │        │            VI:H/VA:N/SC:N/SI:N/SA:N 
│                              │                  │        ╰ V40Score : 5.6 
│                              │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H
│                              │                  │        │           /A:N 
│                              │                  │        ╰ V3Score : 6.5 
│                              │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:H
│                              │                           │           /A:L 
│                              │                           ╰ V3Score : 5.9 
│                              ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2026/07/29/7 
│                              │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-13346 
│                              │                  ├ [2] : https://advisory.echohq.com/cve/CVE-2026-13346 
│                              │                  ├ [3] : https://github.com/pypa/advisory-database/tree/main/v
│                              │                  │       ulns/pip/PYSEC-2026-3721.yaml 
│                              │                  ├ [4] : https://github.com/pypa/pip 
│                              │                  ├ [5] : https://github.com/pypa/pip/commit/10dfb6b9005484578b
│                              │                  │       386f64b9f36982e3dc6679 
│                              │                  ├ [6] : https://github.com/pypa/pip/pull/14110 
│                              │                  ├ [7] : https://mail.python.org/archives/list/security-announ
│                              │                  │       ce@python.org/thread/L2BNQGGVQCEV7DROOORQ7WFKKFF2OOQX
│                              │                  │        
│                              │                  ├ [8] : https://mail.python.org/archives/list/security-announ
│                              │                  │       ce@python.org/thread/L2BNQGGVQCEV7DROOORQ7WFKKFF2OOQX
│                              │                  │       / 
│                              │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-13346 
│                              │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2026-13346 
│                              ├ PublishedDate   : 2026-07-29T19:16:44.267Z 
│                              ╰ LastModifiedDate: 2026-08-20T13:17:44.277Z 
├ [4]  ╭ Target         : usr/bin/prometheus 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                              ├ PkgID           : golang.org/x/crypto@v0.56.0 
│                              ├ PkgName         : golang.org/x/crypto 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.56.0 
│                              │                  ╰ UID : d17ebe8adf3d3b9f 
│                              ├ InstalledVersion: v0.56.0 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:4ab019e27c3f4a6aad9a07bec9d45c15ee47b6e240a3fd21a714d
│                              │                   cd918417e7e 
│                              ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                              │                   unsafe by design, and has known security issues 
│                              ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                              │                    has numerous known security issues, is not maintained, and
│                              │                   should not be used.
│                              │                   
│                              │                   If you are required to interoperate with OpenPGP systems and
│                              │                    need a maintained package, consider
│                              │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                              │                   maintained fork that aims to be a drop-in replacement for
│                              │                   this package. 
│                              ├ Severity        : UNKNOWN 
│                              ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                 ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [5]  ╭ Target         : usr/bin/promtool 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                              ├ PkgID           : golang.org/x/crypto@v0.56.0 
│                              ├ PkgName         : golang.org/x/crypto 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.56.0 
│                              │                  ╰ UID : d6d79aab489f5463 
│                              ├ InstalledVersion: v0.56.0 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:4f3ef10d9d5d5876e21267e7c25420d8b90ebfb8e7c0ba36112c5
│                              │                   f12074a3182 
│                              ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                              │                   unsafe by design, and has known security issues 
│                              ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                              │                    has numerous known security issues, is not maintained, and
│                              │                   should not be used.
│                              │                   
│                              │                   If you are required to interoperate with OpenPGP systems and
│                              │                    need a maintained package, consider
│                              │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                              │                   maintained fork that aims to be a drop-in replacement for
│                              │                   this package. 
│                              ├ Severity        : UNKNOWN 
│                              ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                 ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [6]  ╭ Target         : usr/share/grafana/bin/grafana 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-81870 
│                        │     ├ VendorIDs        ─ [0]: GHSA-8wmf-6v46-5gfg 
│                        │     ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlptrace@v1.44.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlptrace 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                        │     │                  │       lptrace@v1.44.0 
│                        │     │                  ╰ UID : 792f9ddaac96eaa2 
│                        │     ├ InstalledVersion: v1.44.0 
│                        │     ├ FixedVersion    : 1.45.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-81870 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:6894d593114f93acfda9a00c37d606759e602f5300b26f422f888
│                        │     │                   89d0f47ea56 
│                        │     ├ Title           : github.com/open-telemetry/opentelemetry-go:
│                        │     │                   OpenTelemetry-Go: Information disclosure via exporter
│                        │     │                   configuration logging 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From version 1.5.0 to 1.44.0, sdk/trace.NewTracerProvider
│                        │     │                   emits a TracerProvider created internal Info-level
│                        │     │                   diagnostic event whose MarshalLog implementations
│                        │     │                   recursively include span processor, exporter, and client
│                        │     │                   configuration. Applications that call otel.SetLogger to
│                        │     │                   enable OpenTelemetry internal Info logging can therefore
│                        │     │                   record OTLP gRPC and HTTP collector endpoints, the OTLP HTTP
│                        │     │                    Insecure flag, and complete Zipkin collector URLs. A person
│                        │     │                    or system with access to those logs can learn internal
│                        │     │                   collector topology and can recover credentials or tokens
│                        │     │                   embedded in Zipkin URL user information or query strings.
│                        │     │                   The default OpenTelemetry logger does not emit the event,
│                        │     │                   and this path does not log OTLP authentication headers, TLS
│                        │     │                   key material, or span payloads. This issue is fixed in
│                        │     │                   version 1.45.0. 
│                        │     ├ Severity        : LOW 
│                        │     ├ CweIDs           ╭ [0]: CWE-200 
│                        │     │                  ╰ [1]: CWE-532 
│                        │     ├ VendorSeverity   ╭ ghsa  : 1 
│                        │     │                  ╰ redhat: 1 
│                        │     ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/
│                        │     │                  │        │            VI:N/VA:N/SC:N/SI:N/SA:N 
│                        │     │                  │        ╰ V40Score : 2 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 3.3 
│                        │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-81870 
│                        │     │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                        │     │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/com
│                        │     │                  │      mit/3a1412d2b3bc4e4231fbeac2ed42117ae541bb38 
│                        │     │                  ├ [3]: https://github.com/open-telemetry/opentelemetry-go/pul
│                        │     │                  │      l/8438 
│                        │     │                  ├ [4]: https://github.com/open-telemetry/opentelemetry-go/rel
│                        │     │                  │      eases/tag/exporters/zipkin/v1.45.0 
│                        │     │                  ├ [5]: https://github.com/open-telemetry/opentelemetry-go/rel
│                        │     │                  │      eases/tag/sdk/v1.45.0 
│                        │     │                  ├ [6]: https://github.com/open-telemetry/opentelemetry-go/sec
│                        │     │                  │      urity/advisories/GHSA-8wmf-6v46-5gfg 
│                        │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-81870 
│                        │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-81870 
│                        │     ├ PublishedDate   : 2026-09-16T20:17:32.733Z 
│                        │     ╰ LastModifiedDate: 2026-09-30T17:51:56.193Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-81870 
│                        │     ├ VendorIDs        ─ [0]: GHSA-8wmf-6v46-5gfg 
│                        │     ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceg
│                        │     │                   rpc@v1.44.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceg
│                        │     │                   rpc 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                        │     │                  │       lptrace/otlptracegrpc@v1.44.0 
│                        │     │                  ╰ UID : 4767a42b7a237133 
│                        │     ├ InstalledVersion: v1.44.0 
│                        │     ├ FixedVersion    : 1.45.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-81870 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:99cff3e7e6dddce75afaa063b79628321f93cf5a359dbd81a3714
│                        │     │                   03c589f4c6d 
│                        │     ├ Title           : github.com/open-telemetry/opentelemetry-go:
│                        │     │                   OpenTelemetry-Go: Information disclosure via exporter
│                        │     │                   configuration logging 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From version 1.5.0 to 1.44.0, sdk/trace.NewTracerProvider
│                        │     │                   emits a TracerProvider created internal Info-level
│                        │     │                   diagnostic event whose MarshalLog implementations
│                        │     │                   recursively include span processor, exporter, and client
│                        │     │                   configuration. Applications that call otel.SetLogger to
│                        │     │                   enable OpenTelemetry internal Info logging can therefore
│                        │     │                   record OTLP gRPC and HTTP collector endpoints, the OTLP HTTP
│                        │     │                    Insecure flag, and complete Zipkin collector URLs. A person
│                        │     │                    or system with access to those logs can learn internal
│                        │     │                   collector topology and can recover credentials or tokens
│                        │     │                   embedded in Zipkin URL user information or query strings.
│                        │     │                   The default OpenTelemetry logger does not emit the event,
│                        │     │                   and this path does not log OTLP authentication headers, TLS
│                        │     │                   key material, or span payloads. This issue is fixed in
│                        │     │                   version 1.45.0. 
│                        │     ├ Severity        : LOW 
│                        │     ├ CweIDs           ╭ [0]: CWE-200 
│                        │     │                  ╰ [1]: CWE-532 
│                        │     ├ VendorSeverity   ╭ ghsa  : 1 
│                        │     │                  ╰ redhat: 1 
│                        │     ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/
│                        │     │                  │        │            VI:N/VA:N/SC:N/SI:N/SA:N 
│                        │     │                  │        ╰ V40Score : 2 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 3.3 
│                        │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-81870 
│                        │     │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                        │     │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/com
│                        │     │                  │      mit/3a1412d2b3bc4e4231fbeac2ed42117ae541bb38 
│                        │     │                  ├ [3]: https://github.com/open-telemetry/opentelemetry-go/pul
│                        │     │                  │      l/8438 
│                        │     │                  ├ [4]: https://github.com/open-telemetry/opentelemetry-go/rel
│                        │     │                  │      eases/tag/exporters/zipkin/v1.45.0 
│                        │     │                  ├ [5]: https://github.com/open-telemetry/opentelemetry-go/rel
│                        │     │                  │      eases/tag/sdk/v1.45.0 
│                        │     │                  ├ [6]: https://github.com/open-telemetry/opentelemetry-go/sec
│                        │     │                  │      urity/advisories/GHSA-8wmf-6v46-5gfg 
│                        │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-81870 
│                        │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-81870 
│                        │     ├ PublishedDate   : 2026-09-16T20:17:32.733Z 
│                        │     ╰ LastModifiedDate: 2026-09-30T17:51:56.193Z 
│                        ├ [2] ╭ VulnerabilityID : CVE-2026-81870 
│                        │     ├ VendorIDs        ─ [0]: GHSA-8wmf-6v46-5gfg 
│                        │     ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceh
│                        │     │                   ttp@v1.44.0 
│                        │     ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceh
│                        │     │                   ttp 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                        │     │                  │       lptrace/otlptracehttp@v1.44.0 
│                        │     │                  ╰ UID : 50657b12b501c2c2 
│                        │     ├ InstalledVersion: v1.44.0 
│                        │     ├ FixedVersion    : 1.45.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-81870 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:39c7fb62c4d40eb27176e43fa388e25a0ee8da89adb1ccd1f32af
│                        │     │                   d3509f56141 
│                        │     ├ Title           : github.com/open-telemetry/opentelemetry-go:
│                        │     │                   OpenTelemetry-Go: Information disclosure via exporter
│                        │     │                   configuration logging 
│                        │     ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                        │     │                   From version 1.5.0 to 1.44.0, sdk/trace.NewTracerProvider
│                        │     │                   emits a TracerProvider created internal Info-level
│                        │     │                   diagnostic event whose MarshalLog implementations
│                        │     │                   recursively include span processor, exporter, and client
│                        │     │                   configuration. Applications that call otel.SetLogger to
│                        │     │                   enable OpenTelemetry internal Info logging can therefore
│                        │     │                   record OTLP gRPC and HTTP collector endpoints, the OTLP HTTP
│                        │     │                    Insecure flag, and complete Zipkin collector URLs. A person
│                        │     │                    or system with access to those logs can learn internal
│                        │     │                   collector topology and can recover credentials or tokens
│                        │     │                   embedded in Zipkin URL user information or query strings.
│                        │     │                   The default OpenTelemetry logger does not emit the event,
│                        │     │                   and this path does not log OTLP authentication headers, TLS
│                        │     │                   key material, or span payloads. This issue is fixed in
│                        │     │                   version 1.45.0. 
│                        │     ├ Severity        : LOW 
│                        │     ├ CweIDs           ╭ [0]: CWE-200 
│                        │     │                  ╰ [1]: CWE-532 
│                        │     ├ VendorSeverity   ╭ ghsa  : 1 
│                        │     │                  ╰ redhat: 1 
│                        │     ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/
│                        │     │                  │        │            VI:N/VA:N/SC:N/SI:N/SA:N 
│                        │     │                  │        ╰ V40Score : 2 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N
│                        │     │                           │           /A:N 
│                        │     │                           ╰ V3Score : 3.3 
│                        │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-81870 
│                        │     │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                        │     │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/com
│                        │     │                  │      mit/3a1412d2b3bc4e4231fbeac2ed42117ae541bb38 
│                        │     │                  ├ [3]: https://github.com/open-telemetry/opentelemetry-go/pul
│                        │     │                  │      l/8438 
│                        │     │                  ├ [4]: https://github.com/open-telemetry/opentelemetry-go/rel
│                        │     │                  │      eases/tag/exporters/zipkin/v1.45.0 
│                        │     │                  ├ [5]: https://github.com/open-telemetry/opentelemetry-go/rel
│                        │     │                  │      eases/tag/sdk/v1.45.0 
│                        │     │                  ├ [6]: https://github.com/open-telemetry/opentelemetry-go/sec
│                        │     │                  │      urity/advisories/GHSA-8wmf-6v46-5gfg 
│                        │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-81870 
│                        │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-81870 
│                        │     ├ PublishedDate   : 2026-09-16T20:17:32.733Z 
│                        │     ╰ LastModifiedDate: 2026-09-30T17:51:56.193Z 
│                        ╰ [3] ╭ VulnerabilityID : GO-2026-5932 
│                              ├ PkgID           : golang.org/x/crypto@v0.56.0 
│                              ├ PkgName         : golang.org/x/crypto 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.56.0 
│                              │                  ╰ UID : 5f679d24b60e986e 
│                              ├ InstalledVersion: v0.56.0 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:702800d9f53b0ad898fc1e36288ca5e99ffb633ca30e0a9689cb6
│                              │                   3109b7240c2 
│                              ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                              │                   unsafe by design, and has known security issues 
│                              ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                              │                    has numerous known security issues, is not maintained, and
│                              │                   should not be used.
│                              │                   
│                              │                   If you are required to interoperate with OpenPGP systems and
│                              │                    need a maintained package, consider
│                              │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                              │                   maintained fork that aims to be a drop-in replacement for
│                              │                   this package. 
│                              ├ Severity        : UNKNOWN 
│                              ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                 ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [7]  ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_dataso
│      │                  urce_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                              ├ PkgID           : golang.org/x/crypto@v0.56.0 
│                              ├ PkgName         : golang.org/x/crypto 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.56.0 
│                              │                  ╰ UID : af775a6af16fd38b 
│                              ├ InstalledVersion: v0.56.0 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:a53ceed992ff452fd2989375e3cfd043c5cc53136779ccb715973
│                              │                   6b6759a5081 
│                              ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                              │                   unsafe by design, and has known security issues 
│                              ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                              │                    has numerous known security issues, is not maintained, and
│                              │                   should not be used.
│                              │                   
│                              │                   If you are required to interoperate with OpenPGP systems and
│                              │                    need a maintained package, consider
│                              │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                              │                   maintained fork that aims to be a drop-in replacement for
│                              │                   this package. 
│                              ├ Severity        : UNKNOWN 
│                              ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                 ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [8]  ╭ Target         : usr/share/grafana/data/plugins-bundled/grafana-postgresql-datasource/gpx_grafana_post
│      │                  gresql_datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-84445 
│                              ├ VendorIDs        ─ [0]: GHSA-2v4p-qf9q-27wj 
│                              ├ PkgID           : google.golang.org/grpc@v1.83.1 
│                              ├ PkgName         : google.golang.org/grpc 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.1 
│                              │                  ╰ UID : 31726ca2ecc14d3a 
│                              ├ InstalledVersion: v1.83.1 
│                              ├ FixedVersion    : 1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3,
│                              │                   1.85.0-dev.0.20260825072537-93e31b48545e 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84445 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Fingerprint     : sha256:88d1e59d6e8606003bafe97be03df488b0ea34c17d3e5f2f206bf
│                              │                   82ba4567a3d 
│                              ├ Title           : google.golang.org/grpc: gRPC-Go: Denial of Service via
│                              │                   malformed RPC requests 
│                              ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                              │                   1.82.2 and 1.83.2, servers created with xds.NewGRPCServer()
│                              │                   allow internal/transport/http2_server.go to accept an RPC
│                              │                   containing neither the :authority header nor the Host
│                              │                   header, while RouteAndProcess in
│                              │                   internal/xds/server/routing.go assumes that an authority
│                              │                   value exists and indexes the empty slice. A remote client
│                              │                   that can complete transport connection establishment can
│                              │                   trigger an index-out-of-bounds panic that is not recovered
│                              │                   by the per-RPC goroutine and terminates the entire server
│                              │                   process. In insecure or ordinary TLS deployments the request
│                              │                    can be unauthenticated, while strict mTLS or ALTS
│                              │                   deployments require valid transport credentials before the
│                              │                   malformed RPC can reach the interceptor. This issue is fixed
│                              │                    in versions 1.82.2 and 1.83.2. 
│                              ├ Severity        : HIGH 
│                              ├ CweIDs           ╭ [0]: CWE-129 
│                              │                  ╰ [1]: CWE-248 
│                              ├ VendorSeverity   ╭ azure : 3 
│                              │                  ├ ghsa  : 3 
│                              │                  ├ redhat: 3 
│                              │                  ╰ rocky : 3 
│                              ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/
│                              │                  │        │            VI:N/VA:H/SC:N/SI:N/SA:N 
│                              │                  │        ╰ V40Score : 8.7 
│                              │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 7.5 
│                              ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:76743 
│                              │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-84445 
│                              │                  ├ [2] : https://bugzilla.redhat.com/show_bug.cgi?id=2533175 
│                              │                  ├ [3] : https://creativecommons.org/licenses/by/4.0/ 
│                              │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-84445 
│                              │                  ├ [5] : https://errata.rockylinux.org/RLSA-2026:76743 
│                              │                  ├ [6] : https://github.com/grpc/grpc-go 
│                              │                  ├ [7] : https://github.com/grpc/grpc-go/commit/3822494d8ea03b
│                              │                  │       992c089fd2a195f041762fffb7 
│                              │                  ├ [8] : https://github.com/grpc/grpc-go/commit/8668b69c167df9
│                              │                  │       08b6b3666dcbf40992b9e932a4 
│                              │                  ├ [9] : https://github.com/grpc/grpc-go/commit/93e31b48545e2a
│                              │                  │       8aaeb6e06b47fb249f94e6297f 
│                              │                  ├ [10]: https://github.com/grpc/grpc-go/issues/9354 
│                              │                  ├ [11]: https://github.com/grpc/grpc-go/pull/9365 
│                              │                  ├ [12]: https://github.com/grpc/grpc-go/pull/9366 
│                              │                  ├ [13]: https://github.com/grpc/grpc-go/pull/9367 
│                              │                  ├ [14]: https://github.com/grpc/grpc-go/releases/tag/v1.82.2 
│                              │                  ├ [15]: https://github.com/grpc/grpc-go/releases/tag/v1.83.2 
│                              │                  ├ [16]: https://github.com/grpc/grpc-go/security/advisories/G
│                              │                  │       HSA-2v4p-qf9q-27wj 
│                              │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-84445 
│                              │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-84445 
│                              ├ PublishedDate   : 2026-09-14T17:17:51.743Z 
│                              ╰ LastModifiedDate: 2026-09-25T14:10:13.927Z 
├ [9]  ╭ Target  : usr/share/grafana/data/plugins-bundled/grafana-pyroscope-datasource/gpx_grafana-pyroscope-da
│      │           tasource_linux_amd64 
│      ├ Class   : lang-pkgs 
│      ├ Type    : gobinary 
│      ╰ Packages 
├ [10] ╭ Target         : usr/share/grafana/data/plugins-bundled/influxdb/gpx_grafana_influxdb_datasource_linux
│      │                  _amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-84445 
│                              ├ VendorIDs        ─ [0]: GHSA-2v4p-qf9q-27wj 
│                              ├ PkgID           : google.golang.org/grpc@v1.83.1 
│                              ├ PkgName         : google.golang.org/grpc 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.1 
│                              │                  ╰ UID : d958e399d3426dc7 
│                              ├ InstalledVersion: v1.83.1 
│                              ├ FixedVersion    : 1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3,
│                              │                   1.85.0-dev.0.20260825072537-93e31b48545e 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84445 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Fingerprint     : sha256:a77ff42bfeca8cf7fe14596f5b144f258c30199269d7872d6af9c
│                              │                   4047e30a0ce 
│                              ├ Title           : google.golang.org/grpc: gRPC-Go: Denial of Service via
│                              │                   malformed RPC requests 
│                              ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                              │                   1.82.2 and 1.83.2, servers created with xds.NewGRPCServer()
│                              │                   allow internal/transport/http2_server.go to accept an RPC
│                              │                   containing neither the :authority header nor the Host
│                              │                   header, while RouteAndProcess in
│                              │                   internal/xds/server/routing.go assumes that an authority
│                              │                   value exists and indexes the empty slice. A remote client
│                              │                   that can complete transport connection establishment can
│                              │                   trigger an index-out-of-bounds panic that is not recovered
│                              │                   by the per-RPC goroutine and terminates the entire server
│                              │                   process. In insecure or ordinary TLS deployments the request
│                              │                    can be unauthenticated, while strict mTLS or ALTS
│                              │                   deployments require valid transport credentials before the
│                              │                   malformed RPC can reach the interceptor. This issue is fixed
│                              │                    in versions 1.82.2 and 1.83.2. 
│                              ├ Severity        : HIGH 
│                              ├ CweIDs           ╭ [0]: CWE-129 
│                              │                  ╰ [1]: CWE-248 
│                              ├ VendorSeverity   ╭ azure : 3 
│                              │                  ├ ghsa  : 3 
│                              │                  ├ redhat: 3 
│                              │                  ╰ rocky : 3 
│                              ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/
│                              │                  │        │            VI:N/VA:H/SC:N/SI:N/SA:N 
│                              │                  │        ╰ V40Score : 8.7 
│                              │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 7.5 
│                              ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:76743 
│                              │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-84445 
│                              │                  ├ [2] : https://bugzilla.redhat.com/show_bug.cgi?id=2533175 
│                              │                  ├ [3] : https://creativecommons.org/licenses/by/4.0/ 
│                              │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-84445 
│                              │                  ├ [5] : https://errata.rockylinux.org/RLSA-2026:76743 
│                              │                  ├ [6] : https://github.com/grpc/grpc-go 
│                              │                  ├ [7] : https://github.com/grpc/grpc-go/commit/3822494d8ea03b
│                              │                  │       992c089fd2a195f041762fffb7 
│                              │                  ├ [8] : https://github.com/grpc/grpc-go/commit/8668b69c167df9
│                              │                  │       08b6b3666dcbf40992b9e932a4 
│                              │                  ├ [9] : https://github.com/grpc/grpc-go/commit/93e31b48545e2a
│                              │                  │       8aaeb6e06b47fb249f94e6297f 
│                              │                  ├ [10]: https://github.com/grpc/grpc-go/issues/9354 
│                              │                  ├ [11]: https://github.com/grpc/grpc-go/pull/9365 
│                              │                  ├ [12]: https://github.com/grpc/grpc-go/pull/9366 
│                              │                  ├ [13]: https://github.com/grpc/grpc-go/pull/9367 
│                              │                  ├ [14]: https://github.com/grpc/grpc-go/releases/tag/v1.82.2 
│                              │                  ├ [15]: https://github.com/grpc/grpc-go/releases/tag/v1.83.2 
│                              │                  ├ [16]: https://github.com/grpc/grpc-go/security/advisories/G
│                              │                  │       HSA-2v4p-qf9q-27wj 
│                              │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-84445 
│                              │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-84445 
│                              ├ PublishedDate   : 2026-09-14T17:17:51.743Z 
│                              ╰ LastModifiedDate: 2026-09-25T14:10:13.927Z 
├ [11] ╭ Target         : usr/share/grafana/data/plugins-bundled/jaeger/gpx_grafana-jaeger-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-84445 
│                              ├ VendorIDs        ─ [0]: GHSA-2v4p-qf9q-27wj 
│                              ├ PkgID           : google.golang.org/grpc@v1.83.1 
│                              ├ PkgName         : google.golang.org/grpc 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.1 
│                              │                  ╰ UID : 91b797642cce5d78 
│                              ├ InstalledVersion: v1.83.1 
│                              ├ FixedVersion    : 1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3,
│                              │                   1.85.0-dev.0.20260825072537-93e31b48545e 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84445 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Fingerprint     : sha256:40ec6912dc12b335033364f713e827dff90e92210b55836a581e2
│                              │                   91aa3909299 
│                              ├ Title           : google.golang.org/grpc: gRPC-Go: Denial of Service via
│                              │                   malformed RPC requests 
│                              ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                              │                   1.82.2 and 1.83.2, servers created with xds.NewGRPCServer()
│                              │                   allow internal/transport/http2_server.go to accept an RPC
│                              │                   containing neither the :authority header nor the Host
│                              │                   header, while RouteAndProcess in
│                              │                   internal/xds/server/routing.go assumes that an authority
│                              │                   value exists and indexes the empty slice. A remote client
│                              │                   that can complete transport connection establishment can
│                              │                   trigger an index-out-of-bounds panic that is not recovered
│                              │                   by the per-RPC goroutine and terminates the entire server
│                              │                   process. In insecure or ordinary TLS deployments the request
│                              │                    can be unauthenticated, while strict mTLS or ALTS
│                              │                   deployments require valid transport credentials before the
│                              │                   malformed RPC can reach the interceptor. This issue is fixed
│                              │                    in versions 1.82.2 and 1.83.2. 
│                              ├ Severity        : HIGH 
│                              ├ CweIDs           ╭ [0]: CWE-129 
│                              │                  ╰ [1]: CWE-248 
│                              ├ VendorSeverity   ╭ azure : 3 
│                              │                  ├ ghsa  : 3 
│                              │                  ├ redhat: 3 
│                              │                  ╰ rocky : 3 
│                              ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/
│                              │                  │        │            VI:N/VA:H/SC:N/SI:N/SA:N 
│                              │                  │        ╰ V40Score : 8.7 
│                              │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 7.5 
│                              ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:76743 
│                              │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-84445 
│                              │                  ├ [2] : https://bugzilla.redhat.com/show_bug.cgi?id=2533175 
│                              │                  ├ [3] : https://creativecommons.org/licenses/by/4.0/ 
│                              │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-84445 
│                              │                  ├ [5] : https://errata.rockylinux.org/RLSA-2026:76743 
│                              │                  ├ [6] : https://github.com/grpc/grpc-go 
│                              │                  ├ [7] : https://github.com/grpc/grpc-go/commit/3822494d8ea03b
│                              │                  │       992c089fd2a195f041762fffb7 
│                              │                  ├ [8] : https://github.com/grpc/grpc-go/commit/8668b69c167df9
│                              │                  │       08b6b3666dcbf40992b9e932a4 
│                              │                  ├ [9] : https://github.com/grpc/grpc-go/commit/93e31b48545e2a
│                              │                  │       8aaeb6e06b47fb249f94e6297f 
│                              │                  ├ [10]: https://github.com/grpc/grpc-go/issues/9354 
│                              │                  ├ [11]: https://github.com/grpc/grpc-go/pull/9365 
│                              │                  ├ [12]: https://github.com/grpc/grpc-go/pull/9366 
│                              │                  ├ [13]: https://github.com/grpc/grpc-go/pull/9367 
│                              │                  ├ [14]: https://github.com/grpc/grpc-go/releases/tag/v1.82.2 
│                              │                  ├ [15]: https://github.com/grpc/grpc-go/releases/tag/v1.83.2 
│                              │                  ├ [16]: https://github.com/grpc/grpc-go/security/advisories/G
│                              │                  │       HSA-2v4p-qf9q-27wj 
│                              │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-84445 
│                              │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-84445 
│                              ├ PublishedDate   : 2026-09-14T17:17:51.743Z 
│                              ╰ LastModifiedDate: 2026-09-25T14:10:13.927Z 
├ [12] ╭ Target         : usr/share/grafana/data/plugins-bundled/loki/gpx_grafana-loki-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                              ├ PkgID           : golang.org/x/crypto@v0.56.0 
│                              ├ PkgName         : golang.org/x/crypto 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.56.0 
│                              │                  ╰ UID : d65569ac1043cbb3 
│                              ├ InstalledVersion: v0.56.0 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:ff37c8d6fb4a9f9064866184acddab36f3a3f688f0a152f261dd1
│                              │                   6e22d4c6a84 
│                              ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                              │                   unsafe by design, and has known security issues 
│                              ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                              │                    has numerous known security issues, is not maintained, and
│                              │                   should not be used.
│                              │                   
│                              │                   If you are required to interoperate with OpenPGP systems and
│                              │                    need a maintained package, consider
│                              │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                              │                   maintained fork that aims to be a drop-in replacement for
│                              │                   this package. 
│                              ├ Severity        : UNKNOWN 
│                              ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                 ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [13] ╭ Target         : usr/share/grafana/data/plugins-bundled/mssql/gpx_grafana-mssql-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GO-2026-5932 
│                              ├ PkgID           : golang.org/x/crypto@v0.56.0 
│                              ├ PkgName         : golang.org/x/crypto 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.56.0 
│                              │                  ╰ UID : 6017ed04856eb5db 
│                              ├ InstalledVersion: v0.56.0 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:3258aa46e6b748c8552f71bdbddd084df37816a5a34019c790c04
│                              │                   34a445b0bde 
│                              ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                              │                   unsafe by design, and has known security issues 
│                              ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                              │                    has numerous known security issues, is not maintained, and
│                              │                   should not be used.
│                              │                   
│                              │                   If you are required to interoperate with OpenPGP systems and
│                              │                    need a maintained package, consider
│                              │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                              │                   maintained fork that aims to be a drop-in replacement for
│                              │                   this package. 
│                              ├ Severity        : UNKNOWN 
│                              ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                                                 ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
├ [14] ╭ Target  : usr/share/grafana/data/plugins-bundled/mysql/gpx_grafana-mysql-datasource_linux_amd64 
│      ├ Class   : lang-pkgs 
│      ├ Type    : gobinary 
│      ╰ Packages 
├ [15] ╭ Target  : usr/share/grafana/data/plugins-bundled/opentsdb/gpx_grafana-opentsdb-datasource_linux_amd64 
│      ├ Class   : lang-pkgs 
│      ├ Type    : gobinary 
│      ╰ Packages 
├ [16] ╭ Target         : usr/share/grafana/data/plugins-bundled/prometheus/gpx_grafana-prometheus-datasource_l
│      │                  inux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-84445 
│                              ├ VendorIDs        ─ [0]: GHSA-2v4p-qf9q-27wj 
│                              ├ PkgID           : google.golang.org/grpc@v1.83.1 
│                              ├ PkgName         : google.golang.org/grpc 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.1 
│                              │                  ╰ UID : f200b7fd427fcfd 
│                              ├ InstalledVersion: v1.83.1 
│                              ├ FixedVersion    : 1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3,
│                              │                   1.85.0-dev.0.20260825072537-93e31b48545e 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84445 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Fingerprint     : sha256:485227f804f92f59209b5ef10e66a17be5f96272b50115da124ff
│                              │                   0d3d7c4af14 
│                              ├ Title           : google.golang.org/grpc: gRPC-Go: Denial of Service via
│                              │                   malformed RPC requests 
│                              ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                              │                   1.82.2 and 1.83.2, servers created with xds.NewGRPCServer()
│                              │                   allow internal/transport/http2_server.go to accept an RPC
│                              │                   containing neither the :authority header nor the Host
│                              │                   header, while RouteAndProcess in
│                              │                   internal/xds/server/routing.go assumes that an authority
│                              │                   value exists and indexes the empty slice. A remote client
│                              │                   that can complete transport connection establishment can
│                              │                   trigger an index-out-of-bounds panic that is not recovered
│                              │                   by the per-RPC goroutine and terminates the entire server
│                              │                   process. In insecure or ordinary TLS deployments the request
│                              │                    can be unauthenticated, while strict mTLS or ALTS
│                              │                   deployments require valid transport credentials before the
│                              │                   malformed RPC can reach the interceptor. This issue is fixed
│                              │                    in versions 1.82.2 and 1.83.2. 
│                              ├ Severity        : HIGH 
│                              ├ CweIDs           ╭ [0]: CWE-129 
│                              │                  ╰ [1]: CWE-248 
│                              ├ VendorSeverity   ╭ azure : 3 
│                              │                  ├ ghsa  : 3 
│                              │                  ├ redhat: 3 
│                              │                  ╰ rocky : 3 
│                              ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/
│                              │                  │        │            VI:N/VA:H/SC:N/SI:N/SA:N 
│                              │                  │        ╰ V40Score : 8.7 
│                              │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                              │                           │           /A:H 
│                              │                           ╰ V3Score : 7.5 
│                              ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:76743 
│                              │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-84445 
│                              │                  ├ [2] : https://bugzilla.redhat.com/show_bug.cgi?id=2533175 
│                              │                  ├ [3] : https://creativecommons.org/licenses/by/4.0/ 
│                              │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-84445 
│                              │                  ├ [5] : https://errata.rockylinux.org/RLSA-2026:76743 
│                              │                  ├ [6] : https://github.com/grpc/grpc-go 
│                              │                  ├ [7] : https://github.com/grpc/grpc-go/commit/3822494d8ea03b
│                              │                  │       992c089fd2a195f041762fffb7 
│                              │                  ├ [8] : https://github.com/grpc/grpc-go/commit/8668b69c167df9
│                              │                  │       08b6b3666dcbf40992b9e932a4 
│                              │                  ├ [9] : https://github.com/grpc/grpc-go/commit/93e31b48545e2a
│                              │                  │       8aaeb6e06b47fb249f94e6297f 
│                              │                  ├ [10]: https://github.com/grpc/grpc-go/issues/9354 
│                              │                  ├ [11]: https://github.com/grpc/grpc-go/pull/9365 
│                              │                  ├ [12]: https://github.com/grpc/grpc-go/pull/9366 
│                              │                  ├ [13]: https://github.com/grpc/grpc-go/pull/9367 
│                              │                  ├ [14]: https://github.com/grpc/grpc-go/releases/tag/v1.82.2 
│                              │                  ├ [15]: https://github.com/grpc/grpc-go/releases/tag/v1.83.2 
│                              │                  ├ [16]: https://github.com/grpc/grpc-go/security/advisories/G
│                              │                  │       HSA-2v4p-qf9q-27wj 
│                              │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-84445 
│                              │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-84445 
│                              ├ PublishedDate   : 2026-09-14T17:17:51.743Z 
│                              ╰ LastModifiedDate: 2026-09-25T14:10:13.927Z 
├ [17] ╭ Target         : usr/share/grafana/data/plugins-bundled/stackdriver/gpx_grafana_cloudmonitoring_dataso
│      │                  urce_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-56855 
│                        │     ├ VendorIDs        ─ [0]: GO-2026-6355 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.55.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.55.0 
│                        │     │                  ╰ UID : 9ccbbaa632b6534 
│                        │     ├ InstalledVersion: v0.55.0 
│                        │     ├ FixedVersion    : 0.56.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56855 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:8f4cad192a35789d4dba70a1dd6e7477b01118dbc4a4af6f061bb
│                        │     │                   c7467f05294 
│                        │     ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
│                        │     │                   Service via crafted messages 
│                        │     ├ Description     : Previously, after a channel has been established, a
│                        │     │                   malicious peer could send crafted messages that would
│                        │     │                   deadlock the entire connection. Now, we handle all RFC 4254
│                        │     │                   channel messages; global requests are handled explicitly.
│                        │     │                   Then, treat all other messages as a protocol error and tear
│                        │     │                   the connection down instead of buffering and blocking. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs           ─ [0]: CWE-770 
│                        │     ├ VendorSeverity   ╭ alma       : 3 
│                        │     │                  ├ amazon     : 3 
│                        │     │                  ├ azure      : 2 
│                        │     │                  ├ oracle-oval: 3 
│                        │     │                  ├ redhat     : 2 
│                        │     │                  ╰ rocky      : 3 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:70640 
│                        │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-56855 
│                        │     │                  ├ [2] : https://bugzilla.redhat.com/2515815 
│                        │     │                  ├ [3] : https://bugzilla.redhat.com/2515820 
│                        │     │                  ├ [4] : https://bugzilla.redhat.com/2515827 
│                        │     │                  ├ [5] : https://bugzilla.redhat.com/2515838 
│                        │     │                  ├ [6] : https://bugzilla.redhat.com/2515839 
│                        │     │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2402034 
│                        │     │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2503742 
│                        │     │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2515815 
│                        │     │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2515820 
│                        │     │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2515827 
│                        │     │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2515838 
│                        │     │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2515839 
│                        │     │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2528050 
│                        │     │                  ├ [15]: https://creativecommons.org/licenses/by/4.0/ 
│                        │     │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       25-11395 
│                        │     │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-15789 
│                        │     │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-33818 
│                        │     │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-56853 
│                        │     │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-56855 
│                        │     │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-56858 
│                        │     │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-56860 
│                        │     │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-56862 
│                        │     │                  ├ [24]: https://errata.almalinux.org/9/ALSA-2026-70640.html 
│                        │     │                  ├ [25]: https://errata.rockylinux.org/RLSA-2026:70640 
│                        │     │                  ├ [26]: https://go.dev/cl/826524 
│                        │     │                  ├ [27]: https://go.dev/issue/81317 
│                        │     │                  ├ [28]: https://groups.google.com/g/golang-announce/c/1y3fb2n
│                        │     │                  │       p35U 
│                        │     │                  ├ [29]: https://linux.oracle.com/cve/CVE-2026-56855.html 
│                        │     │                  ├ [30]: https://linux.oracle.com/errata/ELSA-2026-70640.html 
│                        │     │                  ├ [31]: https://nvd.nist.gov/vuln/detail/CVE-2026-56855 
│                        │     │                  ├ [32]: https://pkg.go.dev/vuln/GO-2026-6355 
│                        │     │                  ╰ [33]: https://www.cve.org/CVERecord?id=CVE-2026-56855 
│                        │     ├ PublishedDate   : 2026-09-02T20:17:36.397Z 
│                        │     ╰ LastModifiedDate: 2026-09-04T16:34:56.823Z 
│                        ├ [1] ╭ VulnerabilityID : CVE-2026-78662 
│                        │     ├ VendorIDs        ─ [0]: GO-2026-6354 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.55.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.55.0 
│                        │     │                  ╰ UID : 9ccbbaa632b6534 
│                        │     ├ InstalledVersion: v0.55.0 
│                        │     ├ FixedVersion    : 0.56.0 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-78662 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:7a8f635f19c49bebfcf9e0a7226bee09ebbcf74873b0a7d2ef15a
│                        │     │                   05ebc4c2c3e 
│                        │     ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
│                        │     │                   Service via channel request flooding 
│                        │     ├ Description     : Previously, a channel registered in the mux's chanList is
│                        │     │                   not usable until it is established. A malicious peer was
│                        │     │                   able flood the channel's incomingRequests, deadlocking the
│                        │     │                   entire connection. Now, we add an atomic established state,
│                        │     │                   set when a channel becomes usable. Until such a time,
│                        │     │                   handlePacket drops every packet other than the open
│                        │     │                   confirmation/failure, without blocking and without tearing
│                        │     │                   down the connection. 
│                        │     ├ Severity        : MEDIUM 
│                        │     ├ CweIDs           ─ [0]: CWE-770 
│                        │     ├ VendorSeverity   ╭ amazon: 3 
│                        │     │                  ├ azure : 2 
│                        │     │                  ╰ redhat: 2 
│                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:L 
│                        │     │                           ╰ V3Score : 5.3 
│                        │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-78662 
│                        │     │                  ├ [1]: https://go.dev/cl/826504 
│                        │     │                  ├ [2]: https://go.dev/issue/81316 
│                        │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/1y3fb2np
│                        │     │                  │      35U 
│                        │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-78662 
│                        │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6354 
│                        │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-78662 
│                        │     ├ PublishedDate   : 2026-09-02T20:17:37.167Z 
│                        │     ╰ LastModifiedDate: 2026-09-04T16:33:34.057Z 
│                        ├ [2] ╭ VulnerabilityID : GO-2026-5932 
│                        │     ├ PkgID           : golang.org/x/crypto@v0.55.0 
│                        │     ├ PkgName         : golang.org/x/crypto 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.55.0 
│                        │     │                  ╰ UID : 9ccbbaa632b6534 
│                        │     ├ InstalledVersion: v0.55.0 
│                        │     ├ Status          : affected 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ DataSource       ╭ ID  : govulndb 
│                        │     │                  ├ Name: The Go Vulnerability Database 
│                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                        │     ├ Fingerprint     : sha256:77492d6379026869358c8ba0f15841accc4d041bd7001a9b92269
│                        │     │                   f1c662833f3 
│                        │     ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                        │     │                   unsafe by design, and has known security issues 
│                        │     ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                        │     │                    has numerous known security issues, is not maintained, and
│                        │     │                   should not be used.
│                        │     │                   
│                        │     │                   If you are required to interoperate with OpenPGP systems and
│                        │     │                    need a maintained package, consider
│                        │     │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                        │     │                   maintained fork that aims to be a drop-in replacement for
│                        │     │                   this package. 
│                        │     ├ Severity        : UNKNOWN 
│                        │     ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                        │                        ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
│                        ├ [3] ╭ VulnerabilityID : CVE-2026-84304 
│                        │     ├ VendorIDs        ─ [0]: GHSA-vp52-pcj8-j9qc 
│                        │     ├ PkgID           : google.golang.org/grpc@v1.83.0 
│                        │     ├ PkgName         : google.golang.org/grpc 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.0 
│                        │     │                  ╰ UID : b23d41bb2972d10c 
│                        │     ├ InstalledVersion: v1.83.0 
│                        │     ├ FixedVersion    : 1.83.1 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84304 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:a924d7e0e642c9dd5f48dd66a34a113233cab41acbf279789cd60
│                        │     │                   35f995e2c61 
│                        │     ├ Title           : google.golang.org/grpc: gRPC-Go: Denial of Service via
│                        │     │                   HTTP/2 DATA Frame Fragmentation 
│                        │     ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                        │     │                   1.83.1, internal/transport/transport.go stores each
│                        │     │                   fragmented HTTP/2 DATA frame as a separate recvMsg in
│                        │     │                   recvBuffer, so millions of one-byte frames can consume
│                        │     │                   disproportionate heap memory even when payload bytes remain
│                        │     │                   within connection and stream flow-control windows. An
│                        │     │                   unauthenticated remote attacker can use concurrent
│                        │     │                   multiplexed streams to exhaust process memory and cause a
│                        │     │                   runtime panic or out-of-memory termination. Receive-buffer
│                        │     │                   compaction is enabled by default and can be controlled
│                        │     │                   temporarily with
│                        │     │                   GRPC_GO_EXPERIMENTAL_ENABLE_RECEIVE_BUFFER_COMPACTION. This
│                        │     │                   issue is fixed in version 1.83.1. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs           ─ [0]: CWE-400 
│                        │     ├ VendorSeverity   ╭ azure : 3 
│                        │     │                  ├ ghsa  : 3 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/
│                        │     │                  │        │            VI:N/VA:H/SC:N/SI:N/SA:N 
│                        │     │                  │        ╰ V40Score : 8.7 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-84304 
│                        │     │                  ├ [1]: https://github.com/grpc/grpc-go 
│                        │     │                  ├ [2]: https://github.com/grpc/grpc-go/commit/7354d9c8debb4bc
│                        │     │                  │      f2225bf429857078de310c176 
│                        │     │                  ├ [3]: https://github.com/grpc/grpc-go/commit/8cfeca0e1ee5ea0
│                        │     │                  │      980dcc320e20240fa1079ec77 
│                        │     │                  ├ [4]: https://github.com/grpc/grpc-go/pull/9331 
│                        │     │                  ├ [5]: https://github.com/grpc/grpc-go/pull/9333 
│                        │     │                  ├ [6]: https://github.com/grpc/grpc-go/releases/tag/v1.83.1 
│                        │     │                  ├ [7]: https://github.com/grpc/grpc-go/security/advisories/GH
│                        │     │                  │      SA-vp52-pcj8-j9qc 
│                        │     │                  ├ [8]: https://nvd.nist.gov/vuln/detail/CVE-2026-84304 
│                        │     │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-84304 
│                        │     ├ PublishedDate   : 2026-09-01T19:17:30.743Z 
│                        │     ╰ LastModifiedDate: 2026-09-09T21:09:13.08Z 
│                        ├ [4] ╭ VulnerabilityID : CVE-2026-84445 
│                        │     ├ VendorIDs        ─ [0]: GHSA-2v4p-qf9q-27wj 
│                        │     ├ PkgID           : google.golang.org/grpc@v1.83.0 
│                        │     ├ PkgName         : google.golang.org/grpc 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.0 
│                        │     │                  ╰ UID : b23d41bb2972d10c 
│                        │     ├ InstalledVersion: v1.83.0 
│                        │     ├ FixedVersion    : 1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3,
│                        │     │                   1.85.0-dev.0.20260825072537-93e31b48545e 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84445 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:22d004af0a6884f1fb2ad57bd81e5805091b85e5bde27b54f707f
│                        │     │                   2f18b07a22b 
│                        │     ├ Title           : google.golang.org/grpc: gRPC-Go: Denial of Service via
│                        │     │                   malformed RPC requests 
│                        │     ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                        │     │                   1.82.2 and 1.83.2, servers created with xds.NewGRPCServer()
│                        │     │                   allow internal/transport/http2_server.go to accept an RPC
│                        │     │                   containing neither the :authority header nor the Host
│                        │     │                   header, while RouteAndProcess in
│                        │     │                   internal/xds/server/routing.go assumes that an authority
│                        │     │                   value exists and indexes the empty slice. A remote client
│                        │     │                   that can complete transport connection establishment can
│                        │     │                   trigger an index-out-of-bounds panic that is not recovered
│                        │     │                   by the per-RPC goroutine and terminates the entire server
│                        │     │                   process. In insecure or ordinary TLS deployments the request
│                        │     │                    can be unauthenticated, while strict mTLS or ALTS
│                        │     │                   deployments require valid transport credentials before the
│                        │     │                   malformed RPC can reach the interceptor. This issue is fixed
│                        │     │                    in versions 1.82.2 and 1.83.2. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs           ╭ [0]: CWE-129 
│                        │     │                  ╰ [1]: CWE-248 
│                        │     ├ VendorSeverity   ╭ azure : 3 
│                        │     │                  ├ ghsa  : 3 
│                        │     │                  ├ redhat: 3 
│                        │     │                  ╰ rocky : 3 
│                        │     ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/
│                        │     │                  │        │            VI:N/VA:H/SC:N/SI:N/SA:N 
│                        │     │                  │        ╰ V40Score : 8.7 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:76743 
│                        │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-84445 
│                        │     │                  ├ [2] : https://bugzilla.redhat.com/show_bug.cgi?id=2533175 
│                        │     │                  ├ [3] : https://creativecommons.org/licenses/by/4.0/ 
│                        │     │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                        │     │                  │       26-84445 
│                        │     │                  ├ [5] : https://errata.rockylinux.org/RLSA-2026:76743 
│                        │     │                  ├ [6] : https://github.com/grpc/grpc-go 
│                        │     │                  ├ [7] : https://github.com/grpc/grpc-go/commit/3822494d8ea03b
│                        │     │                  │       992c089fd2a195f041762fffb7 
│                        │     │                  ├ [8] : https://github.com/grpc/grpc-go/commit/8668b69c167df9
│                        │     │                  │       08b6b3666dcbf40992b9e932a4 
│                        │     │                  ├ [9] : https://github.com/grpc/grpc-go/commit/93e31b48545e2a
│                        │     │                  │       8aaeb6e06b47fb249f94e6297f 
│                        │     │                  ├ [10]: https://github.com/grpc/grpc-go/issues/9354 
│                        │     │                  ├ [11]: https://github.com/grpc/grpc-go/pull/9365 
│                        │     │                  ├ [12]: https://github.com/grpc/grpc-go/pull/9366 
│                        │     │                  ├ [13]: https://github.com/grpc/grpc-go/pull/9367 
│                        │     │                  ├ [14]: https://github.com/grpc/grpc-go/releases/tag/v1.82.2 
│                        │     │                  ├ [15]: https://github.com/grpc/grpc-go/releases/tag/v1.83.2 
│                        │     │                  ├ [16]: https://github.com/grpc/grpc-go/security/advisories/G
│                        │     │                  │       HSA-2v4p-qf9q-27wj 
│                        │     │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-84445 
│                        │     │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-84445 
│                        │     ├ PublishedDate   : 2026-09-14T17:17:51.743Z 
│                        │     ╰ LastModifiedDate: 2026-09-25T14:10:13.927Z 
│                        ╰ [5] ╭ VulnerabilityID : CVE-2026-84303 
│                              ├ VendorIDs        ─ [0]: GHSA-qc2q-p7wx-3px3 
│                              ├ PkgID           : google.golang.org/grpc@v1.83.0 
│                              ├ PkgName         : google.golang.org/grpc 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.83.0 
│                              │                  ╰ UID : b23d41bb2972d10c 
│                              ├ InstalledVersion: v1.83.0 
│                              ├ FixedVersion    : 1.83.1 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-84303 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Fingerprint     : sha256:c1350789ca5cab5e70d787df134e0ac51014a84bd9fb266b89b6b
│                              │                   a00e278580b 
│                              ├ Title           : gRPC-Go is the Go language implementation of gRPC. Prior to
│                              │                   1.83.1, th ... 
│                              ├ Description     : gRPC-Go is the Go language implementation of gRPC. Prior to
│                              │                   1.83.1, the xDS RBAC HTTP filter in
│                              │                   internal/xds/httpfilter/rbac/rbac.go does not lowercase
│                              │                   header matcher names in normalizeHeaderMatcher even though
│                              │                   incoming metadata keys are lowercase. A DENY policy using a
│                              │                   mixed-case name such as X-Role or User-Agent therefore does
│                              │                   not match and fails open, allowing requests that should be
│                              │                   rejected. The same case mismatch permits :Scheme or
│                              │                   Grpc-Status to evade gRFC A41 validation and prevents Host
│                              │                   from being rewritten to :authority. This issue is fixed in
│                              │                   version 1.83.1. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs           ╭ [0]: CWE-178 
│                              │                  ╰ [1]: CWE-863 
│                              ├ VendorSeverity   ─ ghsa: 2 
│                              ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI
│                              │                         │            :L/VA:N/SC:N/SI:N/SA:N 
│                              │                         ╰ V40Score : 6.3 
│                              ├ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                              │                  ├ [1]: https://github.com/grpc/grpc-go/commit/db9482836c298f2
│                              │                  │      34c896cf82ab68cafc78237f8 
│                              │                  ├ [2]: https://github.com/grpc/grpc-go/commit/ebba6f3f1b206e2
│                              │                  │      b4dc4d1d5a96d18430302c2fe 
│                              │                  ├ [3]: https://github.com/grpc/grpc-go/pull/9332 
│                              │                  ├ [4]: https://github.com/grpc/grpc-go/pull/9335 
│                              │                  ├ [5]: https://github.com/grpc/grpc-go/releases/tag/v1.83.1 
│                              │                  ├ [6]: https://github.com/grpc/grpc-go/security/advisories/GH
│                              │                  │      SA-qc2q-p7wx-3px3 
│                              │                  ╰ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-84303 
│                              ├ PublishedDate   : 2026-09-01T19:17:30.6Z 
│                              ╰ LastModifiedDate: 2026-09-09T21:09:13.08Z 
├ [18] ╭ Target         : usr/share/grafana/data/plugins-bundled/tempo/gpx_grafana-tempo-datasource_linux_amd64 
│      ├ Class          : lang-pkgs 
│      ├ Type           : gobinary 
│      ├ Packages        
│      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-21728 
│                        │     ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                        │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260910130453-bcfe9f230c1d 
│                        │     ├ PkgName         : github.com/grafana/tempo 
│                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20260910
│                        │     │                  │       130453-bcfe9f230c1d 
│                        │     │                  ╰ UID : 26dcfea292072616 
│                        │     ├ InstalledVersion: v1.5.1-0.20260910130453-bcfe9f230c1d 
│                        │     ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                        │     ├ Status          : fixed 
│                        │     ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                        │     │                  │         948373a83d6ca433f6ae 
│                        │     │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                        │     │                            ff5623b7692176c7335f 
│                        │     ├ SeveritySource  : ghsa 
│                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                        │     ├ DataSource       ╭ ID  : ghsa 
│                        │     │                  ├ Name: GitHub Security Advisory Go 
│                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                        │     │                          cosystem%3Ago 
│                        │     ├ Fingerprint     : sha256:bc09761b92ac348048aedf405ea00c63887b62c1adc4c64ffa0b2
│                        │     │                   84def8774b2 
│                        │     ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                        │     ├ Description     : Tempo queries with large limits can cause large memory
│                        │     │                   allocations which can impact the availability of the
│                        │     │                   service, depending on its deployment strategy.
│                        │     │                   
│                        │     │                   Mitigation can be done by setting max_result_limit in the
│                        │     │                   search config, e.g. to 262144 (2^18). Alternatively,
│                        │     │                   automatically restart the service. 
│                        │     ├ Severity        : HIGH 
│                        │     ├ CweIDs           ╭ [0]: CWE-400 
│                        │     │                  ╰ [1]: CWE-770 
│                        │     ├ VendorSeverity   ╭ ghsa  : 3 
│                        │     │                  ╰ redhat: 3 
│                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                  │        │           /A:H 
│                        │     │                  │        ╰ V3Score : 7.5 
│                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                        │     │                           │           /A:H 
│                        │     │                           ╰ V3Score : 7.5 
│                        │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:21769 
│                        │     │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:22347 
│                        │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:22423 
│                        │     │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:23345 
│                        │     │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:24503 
│                        │     │                  ├ [5] : https://access.redhat.com/security/cve/CVE-2026-21728 
│                        │     │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2461395 
│                        │     │                  ├ [7] : https://github.com/grafana/tempo 
│                        │     │                  ├ [8] : https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0
│                        │     │                  │       b67498b662b85a148698b4afd/docs/sources/tempo/release-
│                        │     │                  │       notes/version-2/v2-10.md?plain=1#L328 
│                        │     │                  ├ [9] : https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0
│                        │     │                  │       b67498b662b85a148698b4afd/docs/sources/tempo/release-
│                        │     │                  │       notes/version-2/v2-8.md?plain=1#L251 
│                        │     │                  ├ [10]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0
│                        │     │                  │       b67498b662b85a148698b4afd/docs/sources/tempo/release-
│                        │     │                  │       notes/version-2/v2-9.md?plain=1#L224 
│                        │     │                  ├ [11]: https://github.com/grafana/tempo/commit/650eb1985a077
│                        │     │                  │       6789c8564122990f588a742356f 
│                        │     │                  ├ [12]: https://github.com/grafana/tempo/pull/6525 
│                        │     │                  ├ [13]: https://grafana.com/security/security-advisories/cve-
│                        │     │                  │       2026-21728 
│                        │     │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-21728 
│                        │     │                  ├ [15]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                        │     │                  │       026/cve-2026-21728.json 
│                        │     │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-21728 
│                        │     ├ PublishedDate   : 2026-04-24T09:16:03.71Z 
│                        │     ╰ LastModifiedDate: 2026-09-09T13:18:44.397Z 
│                        ╰ [1] ╭ VulnerabilityID : CVE-2026-28377 
│                              ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                              ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260910130453-bcfe9f230c1d 
│                              ├ PkgName         : github.com/grafana/tempo 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20260910
│                              │                  │       130453-bcfe9f230c1d 
│                              │                  ╰ UID : 26dcfea292072616 
│                              ├ InstalledVersion: v1.5.1-0.20260910130453-bcfe9f230c1d 
│                              ├ FixedVersion    : 2.10.3 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:58c8e0db42d52b8389cfc48e4839848234a99c0c0d1e
│                              │                  │         948373a83d6ca433f6ae 
│                              │                  ╰ DiffID: sha256:d505014454393b9fb122c648705d481b0d4c2af9cc19
│                              │                            ff5623b7692176c7335f 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Fingerprint     : sha256:6d29bbbfde46a35e52599ae4972b46981b4b2919d2ec7f33ef483
│                              │                   5358eb7f69e 
│                              ├ Title           : Grafana Tempo: Grafana Tempo: Information disclosure of S3
│                              │                   encryption key via status config endpoint 
│                              ├ Description     : A vulnerability in Grafana Tempo exposes the S3 SSE-C
│                              │                   encryption key in plaintext through the /status/config
│                              │                   endpoint, potentially allowing unauthorized users to obtain
│                              │                   the key used to encrypt trace data stored in S3.
│                              │                   
│                              │                   Thanks to william_goodfellow for reporting this
│                              │                   vulnerability. 
│                              ├ Severity        : HIGH 
│                              ├ CweIDs           ─ [0]: CWE-326 
│                              ├ VendorSeverity   ╭ ghsa  : 3 
│                              │                  ╰ redhat: 2 
│                              ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N
│                              │                  │        │           /A:N 
│                              │                  │        ╰ V3Score : 7.5 
│                              │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                              │                           │           /A:N 
│                              │                           ╰ V3Score : 6.5 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-28377 
│                              │                  ├ [1]: https://github.com/advisories/GHSA-ffqx-q65f-36jf 
│                              │                  ├ [2]: https://github.com/grafana/tempo 
│                              │                  ├ [3]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                              │                  │      67498b662b85a148698b4afd/CHANGELOG.md?plain=1#L135 
│                              │                  ├ [4]: https://github.com/grafana/tempo/commit/bb8ca663db34a0
│                              │                  │      980c9758b40d918fda3b4dbec3 
│                              │                  ├ [5]: https://grafana.com/security/security-advisories/cve-2
│                              │                  │      026-28377 
│                              │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-28377 
│                              │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-28377 
│                              ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                              ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
╰ [19] ╭ Target  : usr/share/grafana/data/plugins-bundled/zipkin/gpx_grafana-zipkin-datasource_linux_amd64 
       ├ Class   : lang-pkgs 
       ├ Type    : gobinary 
       ╰ Packages 
```

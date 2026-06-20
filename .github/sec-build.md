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
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : 66f3023025d60df9 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:8092ba019a699f73311746f9a6c8ce00c40014ed0c41fe19610afb
│                       │     │                   01f314a435 
│                       │     ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid enc ... 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ─ bitnami: 3 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │     │                  ├ [1]: https://go.dev/issue/79217 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : 66f3023025d60df9 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:e3b0c3d630e4bc2c18a5ad7a62da03ad28479384bb87eeecc4a621
│                       │     │                   3dfd4af10f 
│                       │     ├ Title           : *x509.Certificate).VerifyHostname previously called
│                       │     │                   matchHostnames in ... 
│                       │     ├ Description     : (*x509.Certificate).VerifyHostname previously called
│                       │     │                   matchHostnames in a loop over all DNS Subject Alternative
│                       │     │                   Name (SAN) entries. This caused strings.Split(host, ".") to
│                       │     │                   execute repeatedly on the same input hostname. With a large
│                       │     │                   DNS SAN list, verification costs scaled quadratically based
│                       │     │                   on the number of SAN entries multiplied by the hostname's
│                       │     │                   label count. Because x509.Verify validates hostnames before
│                       │     │                   building the certificate chain, this overhead occurred even
│                       │     │                   for untrusted certificates. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ bitnami: 2 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 6.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │     │                  ├ [1]: https://go.dev/issue/79694 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : 66f3023025d60df9 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                             │                  │         8e6f99dad39e14a2ece 
│                             │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                             │                            91cc80e810a1d1c4bb6 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:f4baeb6762729fbb0c77277345caee10cdc598444cfd408c268fd1
│                             │                   dcb133910f 
│                             ├ Title           : net/textproto: golang: Golang net/textproto: Misleading error
│                             │                    messages via input injection 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ bitnami: 2 
│                             │                  ╰ redhat : 2 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                             │                  │         │           /A:N 
│                             │                  │         ╰ V3Score : 5.3 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
│                             │                  ├ [1]: https://go.dev/cl/777060 
│                             │                  ├ [2]: https://go.dev/issue/79346 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
│                             │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                             ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                             ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : df6aa20024d653e1 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:a81dc15ef65f20d4c1460064d13d3c4872e8618472600c7a40e2dc
│                       │     │                   b8253dd494 
│                       │     ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid enc ... 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ─ bitnami: 3 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │     │                  ├ [1]: https://go.dev/issue/79217 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : df6aa20024d653e1 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:9e3a1501f64ef6684beb3c593d525e9fcd249fa1c01e5d452c94fa
│                       │     │                   741121ad50 
│                       │     ├ Title           : *x509.Certificate).VerifyHostname previously called
│                       │     │                   matchHostnames in ... 
│                       │     ├ Description     : (*x509.Certificate).VerifyHostname previously called
│                       │     │                   matchHostnames in a loop over all DNS Subject Alternative
│                       │     │                   Name (SAN) entries. This caused strings.Split(host, ".") to
│                       │     │                   execute repeatedly on the same input hostname. With a large
│                       │     │                   DNS SAN list, verification costs scaled quadratically based
│                       │     │                   on the number of SAN entries multiplied by the hostname's
│                       │     │                   label count. Because x509.Verify validates hostnames before
│                       │     │                   building the certificate chain, this overhead occurred even
│                       │     │                   for untrusted certificates. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ bitnami: 2 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 6.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │     │                  ├ [1]: https://go.dev/issue/79694 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : df6aa20024d653e1 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                             │                  │         8e6f99dad39e14a2ece 
│                             │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                             │                            91cc80e810a1d1c4bb6 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:2792dc455324df416e393bd4b9153e216abd029c1c667f6e3ddcd9
│                             │                   e301c14bf7 
│                             ├ Title           : net/textproto: golang: Golang net/textproto: Misleading error
│                             │                    messages via input injection 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ bitnami: 2 
│                             │                  ╰ redhat : 2 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                             │                  │         │           /A:N 
│                             │                  │         ╰ V3Score : 5.3 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
│                             │                  ├ [1]: https://go.dev/cl/777060 
│                             │                  ├ [2]: https://go.dev/issue/79346 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
│                             │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                             ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                             ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-21728 
│                       │      ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20251027
│                       │      │                  │       222923-cbe5f845dc7b 
│                       │      │                  ╰ UID : a02c5dcff632fcff 
│                       │      ├ InstalledVersion: v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:e2f501ed7e10f2c21f691d28bbbfb9e7aa0f0a505e5fc00f20b3f
│                       │      │                   69d11ec2d73 
│                       │      ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                       │      ├ Description     : Tempo queries with large limits can cause large memory
│                       │      │                   allocations which can impact the availability of the
│                       │      │                   service, depending on its deployment strategy.
│                       │      │                   
│                       │      │                   Mitigation can be done by setting max_result_limit in the
│                       │      │                   search config, e.g. to 262144 (2^18). 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-400 
│                       │      ├ VendorSeverity   ╭ ghsa  : 3 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-21728 
│                       │      │                  ├ [1]: https://github.com/grafana/tempo 
│                       │      │                  ├ [2]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │      │                  │      67498b662b85a148698b4afd/docs/sources/tempo/release-no
│                       │      │                  │      tes/version-2/v2-10.md?plain=1#L328 
│                       │      │                  ├ [3]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │      │                  │      67498b662b85a148698b4afd/docs/sources/tempo/release-no
│                       │      │                  │      tes/version-2/v2-8.md?plain=1#L251 
│                       │      │                  ├ [4]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │      │                  │      67498b662b85a148698b4afd/docs/sources/tempo/release-no
│                       │      │                  │      tes/version-2/v2-9.md?plain=1#L224 
│                       │      │                  ├ [5]: https://github.com/grafana/tempo/commit/650eb1985a0776
│                       │      │                  │      789c8564122990f588a742356f 
│                       │      │                  ├ [6]: https://github.com/grafana/tempo/pull/6525 
│                       │      │                  ├ [7]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      026-21728 
│                       │      │                  ├ [8]: https://nvd.nist.gov/vuln/detail/CVE-2026-21728 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-21728 
│                       │      ├ PublishedDate   : 2026-04-24T09:16:03.71Z 
│                       │      ╰ LastModifiedDate: 2026-04-24T14:39:28.77Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-28377 
│                       │      ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20251027
│                       │      │                  │       222923-cbe5f845dc7b 
│                       │      │                  ╰ UID : a02c5dcff632fcff 
│                       │      ├ InstalledVersion: v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ FixedVersion    : 2.10.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:9654cc8c83e859db1c5dcafad86264a00e5a3705049679ac2ed3b
│                       │      │                   1473c86c74e 
│                       │      ├ Title           : Grafana Tempo: Grafana Tempo: Information disclosure of S3
│                       │      │                   encryption key via status config endpoint 
│                       │      ├ Description     : A vulnerability in Grafana Tempo exposes the S3 SSE-C
│                       │      │                   encryption key in plaintext through the /status/config
│                       │      │                   endpoint, potentially allowing unauthorized users to obtain
│                       │      │                   the key used to encrypt trace data stored in S3.
│                       │      │                   
│                       │      │                   Thanks to william_goodfellow for reporting this
│                       │      │                   vulnerability. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-326 
│                       │      ├ VendorSeverity   ╭ ghsa  : 3 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-28377 
│                       │      │                  ├ [1]: https://github.com/grafana/tempo 
│                       │      │                  ├ [2]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │      │                  │      67498b662b85a148698b4afd/CHANGELOG.md?plain=1#L135 
│                       │      │                  ├ [3]: https://github.com/grafana/tempo/commit/bb8ca663db34a0
│                       │      │                  │      980c9758b40d918fda3b4dbec3 
│                       │      │                  ├ [4]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      026-28377 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-28377 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-28377 
│                       │      ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                       │      ╰ LastModifiedDate: 2026-03-31T19:00:15.61Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-48096 
│                       │      ├ VendorIDs        ─ [0]: GHSA-8396-jffm-qx4w 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │      │                  ╰ UID : d9f7c327b4e77cd7 
│                       │      ├ InstalledVersion: v1.14.2 
│                       │      ├ FixedVersion    : 1.16.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-48096 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:b1c3affd8216770a6598fed54db3a5aa0bd29bc0d8e8bb1743c31
│                       │      │                   cbcfd3e5e3a 
│                       │      ├ Title           : OpenFGA: OpenFGA: Incorrect authorization due to cache key
│                       │      │                   collision in iterator caching 
│                       │      ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │      │                   developers. Prior to version 1.16.0, when iterator caching
│                       │      │                   is enabled, two distinct check requests can produce the same
│                       │      │                    cache key, leading to OpenFGA reusing an earlier cached
│                       │      │                   result for a subsequent request. This issue has been patched
│                       │      │                    in version 1.16.0. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ╭ [0]: CWE-345 
│                       │      │                  ╰ [1]: CWE-668 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 5 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-48096 
│                       │      │                  ├ [1]: https://github.com/openfga/openfga 
│                       │      │                  ├ [2]: https://github.com/openfga/openfga/releases/tag/v1.16.0 
│                       │      │                  ├ [3]: https://github.com/openfga/openfga/security/advisories
│                       │      │                  │      /GHSA-8396-jffm-qx4w 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-48096 
│                       │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-48096 
│                       │      ├ PublishedDate   : 2026-06-10T16:17:09.397Z 
│                       │      ╰ LastModifiedDate: 2026-06-12T00:46:45.62Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-55689 
│                       │      ├ VendorIDs        ─ [0]: GHSA-hcxc-wf8j-23hv 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │      │                  ╰ UID : d9f7c327b4e77cd7 
│                       │      ├ InstalledVersion: v1.14.2 
│                       │      ├ FixedVersion    : 1.18.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55689 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:95966c37654ebeaeb841e160eaa6fb94379bcb54dc7c533cd4f01
│                       │      │                   a056fc25326 
│                       │      ├ Title           : OpenFGA: OIDC audience validation skipped when
│                       │      │                   --authn-oidc-audience is unset 
│                       │      ├ Description     : ## Description
│                       │      │                   
│                       │      │                   OpenFGA's OIDC authenticator skipped JWT audience (`aud`)
│                       │      │                   validation when no audience was configured.
│                       │      │                   In deployments where one identity provider issues tokens for
│                       │      │                    multiple services,
│                       │      │                   a token minted for an unrelated service could authenticate
│                       │      │                   to OpenFGA.
│                       │      │                   ## Preconditions
│                       │      │                   This applies if the following preconditions are met:
│                       │      │                   1. You run OpenFGA with `authn.method` set to `oidc`.
│                       │      │                   2. You configured `authn.oidc.issuer` but did **not** set
│                       │      │                      `authn.oidc.audience` (`--authn-oidc-audience` /
│                       │      │                   `OPENFGA_AUTHN_OIDC_AUDIENCE`).
│                       │      │                   ## Fix
│                       │      │                   Upgrade to OpenFGA 1.18.0 or greater. OpenFGA now refuses to
│                       │      │                    start in `oidc`
│                       │      │                   mode unless both `authn.oidc.issuer` and
│                       │      │                   `authn.oidc.audience` are set, and the
│                       │      │                   `aud` claim is always validated.
│                       │      │                   ## Acknowledgements
│                       │      │                   OpenFGA would like to thank https://github.com/0xVijay for
│                       │      │                   the report. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N 
│                       │      │                         ╰ V3Score : 6.8 
│                       │      ╰ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │                         ╰ [1]: https://github.com/openfga/openfga/security/advisories
│                       │                                /GHSA-hcxc-wf8j-23hv 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-55170 
│                       │      ├ VendorIDs        ─ [0]: GHSA-cf98-j28v-49v6 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │      │                  ╰ UID : d9f7c327b4e77cd7 
│                       │      ├ InstalledVersion: v1.14.2 
│                       │      ├ FixedVersion    : 1.18.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55170 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ee39e7ff603b37509081bc07801b9e399c468dc370f552e826726
│                       │      │                   00173d573eb 
│                       │      ├ Title           : OpenFGA Improper Policy Enforcement 
│                       │      ├ Description     : ## Description
│                       │      │                   
│                       │      │                   In OpenFGA, when MySQL is being used as the datastore, two
│                       │      │                   distinct check requests can return the same response.
│                       │      │                   ## Preconditions
│                       │      │                   This applies if the following preconditions are met:
│                       │      │                   1. You run OpenFGA with MySQL as the datastore
│                       │      │                   2. Your authorization decisions rely on case-sensitive user
│                       │      │                   strings.
│                       │      │                   ## Fix
│                       │      │                   Upgrade to OpenFGA 1.18.0 or greater.
│                       │      │                   ## Acknowledgements
│                       │      │                   OpenFGA would like to thank @sahajamoth for the detailed
│                       │      │                   report. 
│                       │      ├ Severity        : LOW 
│                       │      ├ VendorSeverity   ─ ghsa: 1 
│                       │      ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI
│                       │      │                         │            :L/VA:N/SC:L/SI:L/SA:N 
│                       │      │                         ╰ V40Score : 2.1 
│                       │      ╰ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │                         ╰ [1]: https://github.com/openfga/openfga/security/advisories
│                       │                                /GHSA-cf98-j28v-49v6 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-42151 
│                       │      ├ VendorIDs        ─ [0]: GHSA-wg65-39gg-5wfj 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.305.3 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.305.3 
│                       │      │                  ╰ UID : 83655859701a095e 
│                       │      ├ InstalledVersion: v0.305.3 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42151 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ac6f3b52a553d9011ea94821d8ac70e27f1663f9a5fd78287e9cf
│                       │      │                   b9b49946fad 
│                       │      ├ Title           : github.com/prometheus/prometheus: Prometheus: Information
│                       │      │                   disclosure of Azure OAuth client secret via config API 
│                       │      ├ Description     : Prometheus is an open-source monitoring system and time
│                       │      │                   series database. Prior to versions 3.5.3 and 3.11.3, the
│                       │      │                   client_secret field in the Azure AD remote write OAuth
│                       │      │                   configuration (storage/remote/azuread) was typed as string
│                       │      │                   instead of Secret. Prometheus redacts fields of type Secret
│                       │      │                   when serving the configuration via the /-/config HTTP API
│                       │      │                   endpoint. Because the field was a plain string, the Azure
│                       │      │                   OAuth client secret was exposed in plaintext to any user or
│                       │      │                   process with access to that endpoint. This issue has been
│                       │      │                   patched in versions 3.5.3 and 3.11.3. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-200 
│                       │      │                  ╰ [1]: CWE-312 
│                       │      ├ VendorSeverity   ╭ azure  : 2 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42151 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/pull/18587 
│                       │      │                  ├ [3]: https://github.com/prometheus/prometheus/pull/18590 
│                       │      │                  ├ [4]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.11.3 
│                       │      │                  ├ [5]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.5.3 
│                       │      │                  ├ [6]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-wg65-39gg-5wfj 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42151 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-42151 
│                       │      ├ PublishedDate   : 2026-05-04T19:16:04.22Z 
│                       │      ╰ LastModifiedDate: 2026-05-11T17:22:07.227Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-40179 
│                       │      ├ VendorIDs        ─ [0]: GHSA-vffh-x6r8-xx99 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.305.3 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.305.3 
│                       │      │                  ╰ UID : 83655859701a095e 
│                       │      ├ InstalledVersion: v0.305.3 
│                       │      ├ FixedVersion    : 0.311.2-0.20260410083055-07c6232d159b 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40179 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:997ed984c8b63a66990679a498546d1673c9a7a92d53f7f732bd0
│                       │      │                   11e80e9bbdb 
│                       │      ├ Title           : Prometheus has Stored XSS via metric names and label values
│                       │      │                   in Prometheus web UI tooltips and metrics explorer 
│                       │      ├ Description     : Prometheus is an open-source monitoring system and time
│                       │      │                   series database. Versions 3.0 through 3.5.1 and 3.6.0
│                       │      │                   through 3.11.1 have stored cross-site scripting
│                       │      │                   vulnerabilities in multiple components of the Prometheus web
│                       │      │                    UI where metric names and label values are injected into
│                       │      │                   innerHTML without escaping. In both the Mantine UI and old
│                       │      │                   React UI, chart tooltips on the Graph page render metric
│                       │      │                   names containing HTML/JavaScript without sanitization. In
│                       │      │                   the old React UI, the Metric Explorer fuzzy search results
│                       │      │                   use dangerouslySetInnerHTML without escaping, and heatmap
│                       │      │                   cell tooltips interpolate le label values without
│                       │      │                   sanitization. With Prometheus v3.x defaulting to UTF-8
│                       │      │                   metric and label name validation, characters like <, >, and
│                       │      │                   " are now valid in metric names and labels. An attacker who
│                       │      │                   can inject metrics via a compromised scrape target, remote
│                       │      │                   write, or OTLP receiver endpoint can execute arbitrary
│                       │      │                   JavaScript in the browser of any Prometheus user who views
│                       │      │                   the metric in the Graph UI, potentially enabling
│                       │      │                   configuration exfiltration, data deletion, or Prometheus
│                       │      │                   shutdown depending on enabled flags. This issue has been
│                       │      │                   fixed in versions 3.5.2 and 3.11.2. If developers are unable
│                       │      │                    to immediately update, the following workarounds are
│                       │      │                   recommended: ensure that the remote write receiver
│                       │      │                   (--web.enable-remote-write-receiver) and the OTLP receiver
│                       │      │                   (--web.enable-otlp-receiver) are not exposed to untrusted
│                       │      │                   sources; verify that all scrape targets are trusted and not
│                       │      │                   under attacker control; avoid enabling admin or mutating API
│                       │      │                    endpoints (e.g., --web.enable-admin-api or
│                       │      │                   --web.enable-lifecycle) in environments where untrusted data
│                       │      │                    may be ingested; and refrain from clicking untrusted links,
│                       │      │                    particularly those containing functions such as
│                       │      │                   label_replace, as they may generate poisoned label names and
│                       │      │                    values. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ╰ nvd    : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N
│                       │      │                  │         │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                  │         ╰ V40Score : 5.3 
│                       │      │                  ├ ghsa    ╭ V3Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                       │      │                  │         │            :L/A:N 
│                       │      │                  │         ├ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N
│                       │      │                  │         │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                  │         ├ V3Score  : 6.1 
│                       │      │                  │         ╰ V40Score : 5.3 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus/commit/07c623
│                       │      │                  │      2d159bfb474a077788be184d87adcfac3c 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/pull/18506 
│                       │      │                  ├ [3]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-vffh-x6r8-xx99 
│                       │      │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-40179 
│                       │      ├ PublishedDate   : 2026-04-15T23:16:09.87Z 
│                       │      ╰ LastModifiedDate: 2026-04-22T20:04:15.1Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-44903 
│                       │      ├ VendorIDs        ─ [0]: GHSA-fw8g-cg8f-9j28 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.305.3 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.305.3 
│                       │      │                  ╰ UID : 83655859701a095e 
│                       │      ├ InstalledVersion: v0.305.3 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-44903 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:a0a3a4e0bf85bd52aeb2078fa247ef15297a4e4642dc5bd6d1e41
│                       │      │                   32fff9a0d7f 
│                       │      ├ Title           : Prometheus is an open-source monitoring system and time
│                       │      │                   series databas ... 
│                       │      ├ Description     : Prometheus is an open-source monitoring system and time
│                       │      │                   series database. From 2.49.0 to before 3.5.3 and 3.11.3, in
│                       │      │                   the Prometheus server's legacy web UI (enabled via the
│                       │      │                   command-line flag --enable-feature=old-ui), the histogram
│                       │      │                   heatmap chart view does not escape le label values when
│                       │      │                   inserting them into the HTML for use as axis tick mark
│                       │      │                   labels. An attacker who can inject crafted metrics can
│                       │      │                   execute JavaScript in the browser of any Prometheus user who
│                       │      │                    views the metric in the heatmap chart UI. This
│                       │      │                   vulnerability is fixed in 3.5.3 and 3.11.3. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ╰ nvd    : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N
│                       │      │                  │         │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                  │         ╰ V40Score : 5.1 
│                       │      │                  ├ ghsa    ╭ V3Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                       │      │                  │         │            :L/A:N 
│                       │      │                  │         ├ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N
│                       │      │                  │         │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                  │         ├ V3Score  : 6.1 
│                       │      │                  │         ╰ V40Score : 5.1 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus/commit/38f23b
│                       │      │                  │      9075ced1de2b82d2dad8b2bebb1ecd5b7d 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-fw8g-cg8f-9j28 
│                       │      │                  ╰ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-44903 
│                       │      ├ PublishedDate   : 2026-05-26T22:16:43.01Z 
│                       │      ╰ LastModifiedDate: 2026-06-05T17:18:32.477Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : 8da4595ba8e1b0f0 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:e8647c2e6296e737f3ba04352ca5fc3b68d766555cac30888045c
│                       │      │                   cff832c57ca 
│                       │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid enc ... 
│                       │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid encoded-words can consume excessive CPU. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ─ bitnami: 3 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │      │                  ├ [1]: https://go.dev/issue/79217 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │      ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-27145 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : 8da4595ba8e1b0f0 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:cb7075a5fead6d186ea23551f85810d25a1630fe6d01c9577f93f
│                       │      │                   d1ab3a7b748 
│                       │      ├ Title           : *x509.Certificate).VerifyHostname previously called
│                       │      │                   matchHostnames in ... 
│                       │      ├ Description     : (*x509.Certificate).VerifyHostname previously called
│                       │      │                   matchHostnames in a loop over all DNS Subject Alternative
│                       │      │                   Name (SAN) entries. This caused strings.Split(host, ".") to
│                       │      │                   execute repeatedly on the same input hostname. With a large
│                       │      │                   DNS SAN list, verification costs scaled quadratically based
│                       │      │                   on the number of SAN entries multiplied by the hostname's
│                       │      │                   label count. Because x509.Verify validates hostnames before
│                       │      │                   building the certificate chain, this overhead occurred even
│                       │      │                   for untrusted certificates. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:H 
│                       │      │                            ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │      │                  ├ [1]: https://go.dev/issue/79694 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
│                       ╰ [10] ╭ VulnerabilityID : CVE-2026-42507 
│                              ├ VendorIDs        ─ [0]: GO-2026-5039 
│                              ├ PkgID           : stdlib@v1.26.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                              │                  ╰ UID : 8da4595ba8e1b0f0 
│                              ├ InstalledVersion: v1.26.3 
│                              ├ FixedVersion    : 1.25.11, 1.26.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                              │                  │         08e6f99dad39e14a2ece 
│                              │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                              │                            791cc80e810a1d1c4bb6 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:aea1bf4aead9234786e1dc0e30413101ceb16cbb4ff3de519c218
│                              │                   75386633df9 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ bitnami: 2 
│                              │                  ╰ redhat : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1]: https://go.dev/cl/777060 
│                              │                  ├ [2]: https://go.dev/issue/79346 
│                              │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                              │                  │      cKw 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                              ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                              ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
╰ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
      │                  rce_linux_amd64 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ├ Packages        
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-33811 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4981 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:02f6f3b8e791d99eb23137f8155a9c374832d8645c7e090294532
                        │      │                   e3f9cec455c 
                        │      ├ Title           : net: golang: Go net package: Denial of Service via long
                        │      │                   CNAME response in LookupCNAME 
                        │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME response can trigger a double-free of C memory
                        │      │                   and a crash. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-415 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ╰ redhat     : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33811 
                        │      │                  ├ [1]: https://go.dev/cl/767860 
                        │      │                  ├ [2]: https://go.dev/issue/78803 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2026-33811.html 
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
                        │      ╰ LastModifiedDate: 2026-05-12T20:23:02.333Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:631718cd7c3bf20409e3e546f304d50ec406333092cbd6582741b
                        │      │                   fa2ecff6773 
                        │      ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infini ... 
                        │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infinite loop of writing CONTINUATION frames if it
                        │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ azure      : 2 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://github.com/golang/go/issues/78476 
                        │      │                  ├ [1] : https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [2] : https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [3] : https://go.dev/cl/761581 
                        │      │                  ├ [4] : https://go.dev/cl/761640 
                        │      │                  ├ [5] : https://go.dev/issue/78476 
                        │      │                  ├ [6] : https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [7] : https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [8] : https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [10]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [11]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-05-13T14:41:59.52Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-39820 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4986 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c97ccb7b6604356f30d2b5c09692fefad3c11922b785bfeb2f0e5
                        │      │                   f4eda298011 
                        │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and Parse ... 
                        │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and ParseDate were able to trigger excessive CPU exhaustion
                        │      │                    and memory allocations. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/759940 
                        │      │                  ├ [1]: https://go.dev/issue/78566 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39820.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4986 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
                        │      ╰ LastModifiedDate: 2026-05-13T15:10:58.65Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-39823 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4982 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7a10b6626f576f2fdd5fc354937d73c184379dc2d22f39be4e642
                        │      │                   afa8d32048d 
                        │      ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly  ... 
                        │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly escaped inside of a <meta> tag's <content>
                        │      │                   attribute. If the URL content were to insert ASCII
                        │      │                   whitespaces around the '=' rune inside of the <content>
                        │      │                   attribute, the escaper would fail to similarly escape it,
                        │      │                   leading to XSS. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://go.dev/cl/769920 
                        │      │                  ├ [1]: https://go.dev/issue/78913 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39823.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39823 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4982 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.29Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:58:45.697Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-39825 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4976 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7424027549b8bb275f4d7c6dfeedc3e525b1743ce807881c437e5
                        │      │                   5e3e247a841 
                        │      ├ Title           : ReverseProxy can forward queries containing parameters not
                        │      │                   visible to  ... 
                        │      ├ Description     : ReverseProxy can forward queries containing parameters not
                        │      │                   visible to Rewrite functions. When used with a Rewrite
                        │      │                   function, or a Director function which parses query
                        │      │                   parameters, ReverseProxy sanitizes the forwarded request to
                        │      │                   remove query parameters which are not parsed by
                        │      │                   url.ParseQuery. ReverseProxy does not take ParseQuery's
                        │      │                   limit on the total number of query parameters (controlled by
                        │      │                    GODEBUG=urlmaxqueryparams=N) into account. This can permit
                        │      │                   ReverseProxy to forward a request containing a query
                        │      │                   parameter that is not visible to the Rewrite function. For
                        │      │                   example, the query "a1=x&a2=x&...&a10000=x&hidden=y" can
                        │      │                   forward the parameter "hidden=y" while hiding it from the
                        │      │                   proxy's Rewrite function. 
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://go.dev/cl/770541 
                        │      │                  ├ [1]: https://go.dev/issue/78948 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39825.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39825 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4976 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.39Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:58:56.39Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:82da16418429072a30486d35317f59f1c8cb8c53f106373c68122
                        │      │                   2238083e622 
                        │      ├ Title           : ELSA-2026-22112:  go-toolset:ol8 security update (IMPORTANT) 
                        │      ├ Description     : The Dial and LookupPort functions panic on Windows when
                        │      │                   provided with an input containing a NUL (0). 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-476 
                        │      ├ VendorSeverity   ╭ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/775320 
                        │      │                  ├ [1]: https://go.dev/issue/79006 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39836.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39836 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4971 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.593Z 
                        │      ╰ LastModifiedDate: 2026-05-13T15:11:10.31Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cf509e94d4aadd86ef747cd9290bba339a05a32807c32131067b3
                        │      │                   6af9fca6226 
                        │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing ... 
                        │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing an email address according to RFC 5322. 
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 3 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/771520 
                        │      │                  ├ [1]: https://go.dev/issue/78987 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-42499.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:59:17.563Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8c150b71040b6f25c650eb04299fd3aef4a0b3ebaccf2810cb855
                        │      │                   4bc3ca76f3b 
                        │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid enc ... 
                        │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid encoded-words can consume excessive CPU. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-407 
                        │      ├ VendorSeverity   ─ bitnami: 3 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/774481 
                        │      │                  ├ [1]: https://go.dev/issue/79217 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
                        │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
                        │      ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c013085f643d1482c173f9839dd6e9737dde8c9134dd9170cfb66
                        │      │                   db969a47200 
                        │      ├ Title           : *x509.Certificate).VerifyHostname previously called
                        │      │                   matchHostnames in ... 
                        │      ├ Description     : (*x509.Certificate).VerifyHostname previously called
                        │      │                   matchHostnames in a loop over all DNS Subject Alternative
                        │      │                   Name (SAN) entries. This caused strings.Split(host, ".") to
                        │      │                   execute repeatedly on the same input hostname. With a large
                        │      │                   DNS SAN list, verification costs scaled quadratically based
                        │      │                   on the number of SAN entries multiplied by the hostname's
                        │      │                   label count. Because x509.Verify validates hostnames before
                        │      │                   building the certificate chain, this overhead occurred even
                        │      │                   for untrusted certificates. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ VendorSeverity   ─ bitnami: 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           L/A:H 
                        │      │                            ╰ V3Score : 6.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/783621 
                        │      │                  ├ [1]: https://go.dev/issue/79694 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-39826 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4980 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8162493545d36fe0961f5974e1b183ed8444915dac81b3d4c5256
                        │      │                   95fb986e58e 
                        │      ├ Title           : html/template: golang: html/template: Cross-site scripting
                        │      │                   due to incorrect script tag escaping 
                        │      ├ Description     : If a trusted template author were to write a <script> tag
                        │      │                   containing an empty 'type' attribute or a 'type' attribute
                        │      │                   with an ASCII whitespace, the execution of the template
                        │      │                   would incorrectly escape any data passed into the <script>
                        │      │                   block. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-116 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 2 
                        │      │                  ╰ redhat     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 5.4 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39826 
                        │      │                  ├ [1]: https://go.dev/cl/771180 
                        │      │                  ├ [2]: https://go.dev/issue/78981 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2026-39826.html 
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4980 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39826 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:59:07.48Z 
                        ╰ [10] ╭ VulnerabilityID : CVE-2026-42507 
                               ├ VendorIDs        ─ [0]: GO-2026-5039 
                               ├ PkgID           : stdlib@v1.26.2 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                               │                  ╰ UID : 83c42d84cdb2ccfe 
                               ├ InstalledVersion: v1.26.2 
                               ├ FixedVersion    : 1.25.11, 1.26.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                               │                  │         08e6f99dad39e14a2ece 
                               │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                               │                            791cc80e810a1d1c4bb6 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:cfa8b47574116ee0d929680a01e879ac02620a1c6698bb2007624
                               │                   77acbbfff9d 
                               ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                               │                   error messages via input injection 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : MEDIUM 
                               ├ VendorSeverity   ╭ bitnami: 2 
                               │                  ╰ redhat : 2 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 5.3 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                            │           L/A:N 
                               │                            ╰ V3Score : 5.3 
                               ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
                               │                  ├ [1]: https://go.dev/cl/777060 
                               │                  ├ [2]: https://go.dev/issue/79346 
                               │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                               │                  │      cKw 
                               │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                               │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
                               │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-06-04T16:15:50.143Z 
```

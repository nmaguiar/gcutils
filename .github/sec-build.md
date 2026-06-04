```yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.24.0_alpha20260127) 
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
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : 66f3023025d60df9 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c8
│                       │     │                  │         4e4c304a53b964ae1af 
│                       │     │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1aa
│                       │     │                            f5b9fb7eae16eed715f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:341b66d050dbae7df88c30aa3093ba35f98ed1fb13e47cd7d59d38
│                       │     │                   5737e5824c 
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
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │     │                  ├ [1]: https://go.dev/issue/79694 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-06-02T23:16:35.57Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : 66f3023025d60df9 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c8
│                       │     │                  │         4e4c304a53b964ae1af 
│                       │     │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1aa
│                       │     │                            f5b9fb7eae16eed715f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:fa42f94df2dcc71f0e973f0ba7e61e67e5cfd716f753a3eac4661b
│                       │     │                   e035270635 
│                       │     ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid enc ... 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │     │                  ├ [1]: https://go.dev/issue/79217 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-06-03T16:16:30.157Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : 66f3023025d60df9 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c8
│                             │                  │         4e4c304a53b964ae1af 
│                             │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1aa
│                             │                            f5b9fb7eae16eed715f 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:5966f35d0d11c4033da1ba20ce167e0329a8ff279f1649d3ecb947
│                             │                   42089482f6 
│                             ├ Title           : When returning errors, functions in the net/textproto package
│                             │                    would in ... 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/777060 
│                             │                  ├ [1]: https://go.dev/issue/79346 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5039 
│                             ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                             ╰ LastModifiedDate: 2026-06-03T20:16:20.65Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : df6aa20024d653e1 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c8
│                       │     │                  │         4e4c304a53b964ae1af 
│                       │     │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1aa
│                       │     │                            f5b9fb7eae16eed715f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:e6215588ef4e7b824249d9e074f7a58328ff13b1efa14cc407b9f2
│                       │     │                   06a62b3883 
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
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │     │                  ├ [1]: https://go.dev/issue/79694 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-06-02T23:16:35.57Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : df6aa20024d653e1 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c8
│                       │     │                  │         4e4c304a53b964ae1af 
│                       │     │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1aa
│                       │     │                            f5b9fb7eae16eed715f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:2c7a5476c03698412466cf9458b2ec6e61e1866189caccb5e354f5
│                       │     │                   1c42e134e7 
│                       │     ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid enc ... 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │     │                  ├ [1]: https://go.dev/issue/79217 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-06-03T16:16:30.157Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : df6aa20024d653e1 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c8
│                             │                  │         4e4c304a53b964ae1af 
│                             │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1aa
│                             │                            f5b9fb7eae16eed715f 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:16ddf4d7c935847cbc72c816644bf29cc7b36a88fe064a2bf80ea6
│                             │                   b91a9fff49 
│                             ├ Title           : When returning errors, functions in the net/textproto package
│                             │                    would in ... 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/777060 
│                             │                  ├ [1]: https://go.dev/issue/79346 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5039 
│                             ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                             ╰ LastModifiedDate: 2026-06-03T20:16:20.65Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-32952 
│                       │      ├ VendorIDs        ─ [0]: GHSA-pjcq-xvwq-hhpj 
│                       │      ├ PkgID           : github.com/Azure/go-ntlmssp@v0.0.0-20220621081337-cb9428e4ac1e 
│                       │      ├ PkgName         : github.com/Azure/go-ntlmssp 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/azure/go-ntlmssp@v0.0.0-2022062
│                       │      │                  │       1081337-cb9428e4ac1e 
│                       │      │                  ╰ UID : 934d0dc857764403 
│                       │      ├ InstalledVersion: v0.0.0-20220621081337-cb9428e4ac1e 
│                       │      ├ FixedVersion    : 0.1.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32952 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:e16fff5c31d509e5a4a3eff5cba13b9aa3e2830b614760f7555ea
│                       │      │                   c381400734c 
│                       │      ├ Title           : go-ntlmssp: go-ntlmssp: Denial of Service via malicious NTLM
│                       │      │                    challenge 
│                       │      ├ Description     : go-ntlmssp is a Go package that provides NTLM/Negotiate
│                       │      │                   authentication over HTTP. Prior to version 0.1.1, a
│                       │      │                   malicious NTLM challenge message can causes an slice out of
│                       │      │                   bounds panic, which can crash any Go process using
│                       │      │                   `ntlmssp.Negotiator` as an HTTP transport. Version 0.1.1
│                       │      │                   patches the issue. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-190 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 3 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 5.3 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-32952 
│                       │      │                  ├ [1]: https://github.com/Azure/go-ntlmssp 
│                       │      │                  ├ [2]: https://github.com/Azure/go-ntlmssp/releases/tag/v0.1.1 
│                       │      │                  ├ [3]: https://github.com/Azure/go-ntlmssp/security/advisorie
│                       │      │                  │      s/GHSA-pjcq-xvwq-hhpj 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-32952 
│                       │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-32952 
│                       │      ├ PublishedDate   : 2026-04-24T03:16:07.833Z 
│                       │      ╰ LastModifiedDate: 2026-05-21T18:22:06.247Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-41602 
│                       │      ├ VendorIDs        ─ [0]: GHSA-wf45-q9ch-q8gh 
│                       │      ├ PkgID           : github.com/apache/thrift@v0.22.0 
│                       │      ├ PkgName         : github.com/apache/thrift 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/apache/thrift@v0.22.0 
│                       │      │                  ╰ UID : 7cca386d01b6c3b2 
│                       │      ├ InstalledVersion: v0.22.0 
│                       │      ├ FixedVersion    : 0.23.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41602 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:30c859bee9bcc907aa28b78364ec1df8d0563621acbffa5499909
│                       │      │                   93e1d3ef57f 
│                       │      ├ Title           : github.com/apache/thrift: Apache Thrift: Integer Overflow in
│                       │      │                    TFramedTransport Go implementation 
│                       │      ├ Description     : Integer Overflow or Wraparound vulnerability in Apache
│                       │      │                   Thrift TFramedTransport Go language implementation
│                       │      │                   
│                       │      │                   This issue affects Apache Thrift: before 0.23.0.
│                       │      │                   Users are recommended to upgrade to version 0.23.0, which
│                       │      │                   fixes the issue. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-190 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ├ azure  : 3 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: http://www.openwall.com/lists/oss-security/2026/04/28/6 
│                       │      │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2026-41602 
│                       │      │                  ├ [2]: https://github.com/apache/thrift 
│                       │      │                  ├ [3]: https://lists.apache.org/thread/lb4j0zyd5f3g36cos0wql9
│                       │      │                  │      25przpnwql 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-41602 
│                       │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-41602 
│                       │      ├ PublishedDate   : 2026-04-28T10:16:03Z 
│                       │      ╰ LastModifiedDate: 2026-04-28T18:40:25.53Z 
│                       ├ [2]  ╭ VulnerabilityID : GHSA-xmrv-pmrh-hhx2 
│                       │      ├ PkgID           : github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream@v1.7.3 
│                       │      ├ PkgName         : github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/aws/aws-sdk-go-v2/aws/protocol/
│                       │      │                  │       eventstream@v1.7.3 
│                       │      │                  ╰ UID : 887ac96dc9e4911b 
│                       │      ├ InstalledVersion: v1.7.3 
│                       │      ├ FixedVersion    : 1.7.8 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://github.com/advisories/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:2a7aed9b443a176f1ccfa3c43c765849e7be78d6dfca327e4d4a8
│                       │      │                   734f53d3279 
│                       │      ├ Title           : Denial of Service due to Panic in AWS SDK for Go v2 SDK
│                       │      │                   EventStream Decoder 
│                       │      ├ Description     : **CVSSv3.1 Rating**: [Medium]
│                       │      │                   **CVSSv3.1 Score**: [5.9]
│                       │      │                   **CVSSv3.1 Vector String**:
│                       │      │                   [CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H]
│                       │      │                   
│                       │      │                   ## Summary and Impact
│                       │      │                   An issue exists in the the EventStream header decoder in AWS
│                       │      │                    SDK for Go v2 in versions predating
│                       │      │                   [2026-03-23](https://github.com/aws/aws-sdk-go-v2/releases/t
│                       │      │                   ag/release-2026-03-23). An actor can send a malformed
│                       │      │                   EventStream response frame containing a crafted header value
│                       │      │                    type byte outside the valid range, which can cause the host
│                       │      │                    process to terminate.
│                       │      │                   Impacted versions: <
│                       │      │                   ag/release-2026-03-23)
│                       │      │                   ## Patches
│                       │      │                   This issue has been addressed in versions
│                       │      │                   ag/release-2026-03-23) and above. We recommend upgrading to
│                       │      │                   the latest version and ensuring any forked or derivative
│                       │      │                   code is patched to incorporate the new fixes. 
│                       │      │                   ## Workarounds
│                       │      │                   Not Applicable
│                       │      │                   ## References
│                       │      │                   If you have any questions or comments about this advisory,
│                       │      │                   we ask that you contact [AWS/Amazon] Security via our
│                       │      │                   [vulnerability reporting
│                       │      │                   page](https://aws.amazon.com/security/vulnerability-reportin
│                       │      │                   g) or directly via email to
│                       │      │                   [aws-security@amazon.com](mailto:aws-security@amazon.com).
│                       │      │                   Please do not create a public GitHub issue. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H 
│                       │      │                         ╰ V3Score : 5.9 
│                       │      ├ References       ╭ [0]: https://github.com/aws/aws-sdk-go-v2 
│                       │      │                  ├ [1]: https://github.com/aws/aws-sdk-go-v2/releases/tag/rele
│                       │      │                  │      ase-2026-03-23 
│                       │      │                  ╰ [2]: https://github.com/aws/aws-sdk-go-v2/security/advisori
│                       │      │                         es/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ PublishedDate   : 2026-04-08T00:18:56Z 
│                       │      ╰ LastModifiedDate: 2026-04-08T00:18:57Z 
│                       ├ [3]  ╭ VulnerabilityID : GHSA-xmrv-pmrh-hhx2 
│                       │      ├ PkgID           : github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs@v1.51.0 
│                       │      ├ PkgName         : github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/aws/aws-sdk-go-v2/service/cloud
│                       │      │                  │       watchlogs@v1.51.0 
│                       │      │                  ╰ UID : 681eda24292030ae 
│                       │      ├ InstalledVersion: v1.51.0 
│                       │      ├ FixedVersion    : 1.65.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://github.com/advisories/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:04c6637db04972a0480b3b6052c83acda6751b85c047f4196fe10
│                       │      │                   c5b2ce7e1dc 
│                       │      ├ Title           : Denial of Service due to Panic in AWS SDK for Go v2 SDK
│                       │      │                   EventStream Decoder 
│                       │      ├ Description     : **CVSSv3.1 Rating**: [Medium]
│                       │      │                   **CVSSv3.1 Score**: [5.9]
│                       │      │                   **CVSSv3.1 Vector String**:
│                       │      │                   [CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H]
│                       │      │                   
│                       │      │                   ## Summary and Impact
│                       │      │                   An issue exists in the the EventStream header decoder in AWS
│                       │      │                    SDK for Go v2 in versions predating
│                       │      │                   [2026-03-23](https://github.com/aws/aws-sdk-go-v2/releases/t
│                       │      │                   ag/release-2026-03-23). An actor can send a malformed
│                       │      │                   EventStream response frame containing a crafted header value
│                       │      │                    type byte outside the valid range, which can cause the host
│                       │      │                    process to terminate.
│                       │      │                   Impacted versions: <
│                       │      │                   ag/release-2026-03-23)
│                       │      │                   ## Patches
│                       │      │                   This issue has been addressed in versions
│                       │      │                   ag/release-2026-03-23) and above. We recommend upgrading to
│                       │      │                   the latest version and ensuring any forked or derivative
│                       │      │                   code is patched to incorporate the new fixes. 
│                       │      │                   ## Workarounds
│                       │      │                   Not Applicable
│                       │      │                   ## References
│                       │      │                   If you have any questions or comments about this advisory,
│                       │      │                   we ask that you contact [AWS/Amazon] Security via our
│                       │      │                   [vulnerability reporting
│                       │      │                   page](https://aws.amazon.com/security/vulnerability-reportin
│                       │      │                   g) or directly via email to
│                       │      │                   [aws-security@amazon.com](mailto:aws-security@amazon.com).
│                       │      │                   Please do not create a public GitHub issue. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H 
│                       │      │                         ╰ V3Score : 5.9 
│                       │      ├ References       ╭ [0]: https://github.com/aws/aws-sdk-go-v2 
│                       │      │                  ├ [1]: https://github.com/aws/aws-sdk-go-v2/releases/tag/rele
│                       │      │                  │      ase-2026-03-23 
│                       │      │                  ╰ [2]: https://github.com/aws/aws-sdk-go-v2/security/advisori
│                       │      │                         es/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ PublishedDate   : 2026-04-08T00:18:56Z 
│                       │      ╰ LastModifiedDate: 2026-04-08T00:18:57Z 
│                       ├ [4]  ╭ VulnerabilityID : GHSA-xmrv-pmrh-hhx2 
│                       │      ├ PkgID           : github.com/aws/aws-sdk-go-v2/service/s3@v1.89.2 
│                       │      ├ PkgName         : github.com/aws/aws-sdk-go-v2/service/s3 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/aws/aws-sdk-go-v2/service/s3@v1
│                       │      │                  │       .89.2 
│                       │      │                  ╰ UID : 93a0a24061cc1a4e 
│                       │      ├ InstalledVersion: v1.89.2 
│                       │      ├ FixedVersion    : 1.97.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://github.com/advisories/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:894979efe5fe194ef7833f8b76bbc37177aa9568fd13ba70b645d
│                       │      │                   4fd13ab709a 
│                       │      ├ Title           : Denial of Service due to Panic in AWS SDK for Go v2 SDK
│                       │      │                   EventStream Decoder 
│                       │      ├ Description     : **CVSSv3.1 Rating**: [Medium]
│                       │      │                   **CVSSv3.1 Score**: [5.9]
│                       │      │                   **CVSSv3.1 Vector String**:
│                       │      │                   [CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H]
│                       │      │                   
│                       │      │                   ## Summary and Impact
│                       │      │                   An issue exists in the the EventStream header decoder in AWS
│                       │      │                    SDK for Go v2 in versions predating
│                       │      │                   [2026-03-23](https://github.com/aws/aws-sdk-go-v2/releases/t
│                       │      │                   ag/release-2026-03-23). An actor can send a malformed
│                       │      │                   EventStream response frame containing a crafted header value
│                       │      │                    type byte outside the valid range, which can cause the host
│                       │      │                    process to terminate.
│                       │      │                   Impacted versions: <
│                       │      │                   ag/release-2026-03-23)
│                       │      │                   ## Patches
│                       │      │                   This issue has been addressed in versions
│                       │      │                   ag/release-2026-03-23) and above. We recommend upgrading to
│                       │      │                   the latest version and ensuring any forked or derivative
│                       │      │                   code is patched to incorporate the new fixes. 
│                       │      │                   ## Workarounds
│                       │      │                   Not Applicable
│                       │      │                   ## References
│                       │      │                   If you have any questions or comments about this advisory,
│                       │      │                   we ask that you contact [AWS/Amazon] Security via our
│                       │      │                   [vulnerability reporting
│                       │      │                   page](https://aws.amazon.com/security/vulnerability-reportin
│                       │      │                   g) or directly via email to
│                       │      │                   [aws-security@amazon.com](mailto:aws-security@amazon.com).
│                       │      │                   Please do not create a public GitHub issue. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H 
│                       │      │                         ╰ V3Score : 5.9 
│                       │      ├ References       ╭ [0]: https://github.com/aws/aws-sdk-go-v2 
│                       │      │                  ├ [1]: https://github.com/aws/aws-sdk-go-v2/releases/tag/rele
│                       │      │                  │      ase-2026-03-23 
│                       │      │                  ╰ [2]: https://github.com/aws/aws-sdk-go-v2/security/advisori
│                       │      │                         es/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ PublishedDate   : 2026-04-08T00:18:56Z 
│                       │      ╰ LastModifiedDate: 2026-04-08T00:18:57Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-21726 
│                       │      ├ VendorIDs        ─ [0]: GHSA-497x-rrr9-68jp 
│                       │      ├ PkgID           : github.com/grafana/loki/v3@v3.5.11 
│                       │      ├ PkgName         : github.com/grafana/loki/v3 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/loki/v3@v3.5.11 
│                       │      │                  ╰ UID : ea30b0fe161ac100 
│                       │      ├ InstalledVersion: v3.5.11 
│                       │      ├ FixedVersion    : 3.6.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21726 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:7a321eb0ec1725711fb80d08c70a0ca8ff60f2409714568b60d83
│                       │      │                   f65f8eb15f1 
│                       │      ├ Title           : Loki: Loki: Information disclosure via path traversal
│                       │      │                   vulnerability 
│                       │      ├ Description     : The CVE-2021-36156 fix validates the namespace parameter for
│                       │      │                    path traversal sequences after a single URL decode, by
│                       │      │                   double encoding, an attacker can read files at the Ruler API
│                       │      │                    endpoint /loki/api/v1/rules/{namespace}
│                       │      │                   
│                       │      │                   Thanks to Prasanth Sundararajan for reporting this
│                       │      │                   vulnerability. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-22 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-21726 
│                       │      │                  ├ [1]: https://github.com/grafana/loki 
│                       │      │                  ├ [2]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      026-21726 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-21726 
│                       │      │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2026-21726 
│                       │      ├ PublishedDate   : 2026-04-15T20:16:34.177Z 
│                       │      ╰ LastModifiedDate: 2026-04-20T20:08:40.723Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-21728 
│                       │      ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20250529124718-87c2dc380cec 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20250529
│                       │      │                  │       124718-87c2dc380cec 
│                       │      │                  ╰ UID : 588431602d21b47d 
│                       │      ├ InstalledVersion: v1.5.1-0.20250529124718-87c2dc380cec 
│                       │      ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:0d34e83f631a328a91bfad24804cb067e9758ca5febd14fec0e5f
│                       │      │                   243e3427d25 
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
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-28377 
│                       │      ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20250529124718-87c2dc380cec 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20250529
│                       │      │                  │       124718-87c2dc380cec 
│                       │      │                  ╰ UID : 588431602d21b47d 
│                       │      ├ InstalledVersion: v1.5.1-0.20250529124718-87c2dc380cec 
│                       │      ├ FixedVersion    : 2.10.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:7892116abf0d76e1e95cc25d191243bd66f3b45600a90a5498c58
│                       │      │                   d299ba7d137 
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
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-33816 
│                       │      ├ VendorIDs        ─ [0]: GHSA-9jj7-4m8r-rfcm 
│                       │      ├ PkgID           : github.com/jackc/pgx/v5@v5.8.0 
│                       │      ├ PkgName         : github.com/jackc/pgx/v5 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/jackc/pgx/v5@v5.8.0 
│                       │      │                  ╰ UID : 2c685c55374d6682 
│                       │      ├ InstalledVersion: v5.8.0 
│                       │      ├ FixedVersion    : 5.9.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33816 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:9e96f34d999f13cf29ce8e50598fd69cfbaecf101d4f6e1b7ea3d
│                       │      │                   fa005577ac5 
│                       │      ├ Title           : github.com/jackc/pgx/v5: github.com/jackc/pgx: Memory-safety
│                       │      │                    vulnerability 
│                       │      ├ Description     : Memory-safety vulnerability in github.com/jackc/pgx/v5. 
│                       │      ├ Severity        : CRITICAL 
│                       │      ├ VendorSeverity   ╭ alma  : 3 
│                       │      │                  ├ ghsa  : 4 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 8.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/errata/RHSA-2026:19137 
│                       │      │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2026-33816 
│                       │      │                  ├ [2]: https://bugzilla.redhat.com/2455972 
│                       │      │                  ├ [3]: https://bugzilla.redhat.com/2456338 
│                       │      │                  ├ [4]: https://errata.almalinux.org/10/ALSA-2026-19137.html 
│                       │      │                  ├ [5]: https://github.com/jackc/pgx 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-33816 
│                       │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4772 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-33816 
│                       │      ├ PublishedDate   : 2026-04-07T16:16:24.92Z 
│                       │      ╰ LastModifiedDate: 2026-05-21T19:58:43.39Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-41889 
│                       │      ├ VendorIDs        ─ [0]: GHSA-j88v-2chj-qfwx 
│                       │      ├ PkgID           : github.com/jackc/pgx/v5@v5.8.0 
│                       │      ├ PkgName         : github.com/jackc/pgx/v5 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/jackc/pgx/v5@v5.8.0 
│                       │      │                  ╰ UID : 2c685c55374d6682 
│                       │      ├ InstalledVersion: v5.8.0 
│                       │      ├ FixedVersion    : 5.9.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41889 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:23d94f3c59231b265e766bf18bfb307a10d6455727c920b5848c2
│                       │      │                   9abba0ea8d9 
│                       │      ├ Title           : github.com/jackc/pgx: golang: pgx: SQL injection via
│                       │      │                   specific SQL query conditions 
│                       │      ├ Description     : pgx is a PostgreSQL driver and toolkit for Go. Prior to
│                       │      │                   version 5.9.2, SQL injection can occur when the non-default
│                       │      │                   simple protocol is used, a dollar quoted string literal is
│                       │      │                   used in the SQL query, that string literal contains text
│                       │      │                   that would be would be interpreted as a placeholder outside
│                       │      │                   of a string literal, and the value of that placeholder is
│                       │      │                   controllable by the attacker. This issue has been patched in
│                       │      │                    version 5.9.2. 
│                       │      ├ Severity        : LOW 
│                       │      ├ CweIDs           ─ [0]: CWE-89 
│                       │      ├ VendorSeverity   ╭ ghsa  : 1 
│                       │      │                  ├ nvd   : 4 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/
│                       │      │                  │        │            VI:L/VA:N/SC:N/SI:N/SA:N 
│                       │      │                  │        ╰ V40Score : 2.3 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 5.9 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-41889 
│                       │      │                  ├ [1]: https://github.com/jackc/pgx 
│                       │      │                  ├ [2]: https://github.com/jackc/pgx/commit/60644f84918a8af66d
│                       │      │                  │      14a4b0d865d4edafd955da 
│                       │      │                  ├ [3]: https://github.com/jackc/pgx/releases/tag/v5.9.2 
│                       │      │                  ├ [4]: https://github.com/jackc/pgx/security/advisories/GHSA-
│                       │      │                  │      j88v-2chj-qfwx 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-41889 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-41889 
│                       │      ├ PublishedDate   : 2026-05-08T17:16:31.04Z 
│                       │      ╰ LastModifiedDate: 2026-05-21T19:58:12.45Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-34040 
│                       │      ├ VendorIDs        ─ [0]: GHSA-x744-4wpc-v9h2 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ FixedVersion    : 29.3.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-34040 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:48d28159638951826672294c2d5d80a41f3041d0070857b1b274a
│                       │      │                   ccba9384ef6 
│                       │      ├ Title           : Moby: Moby: Authorization bypass vulnerability 
│                       │      ├ Description     : Moby is an open source container framework. Prior to version
│                       │      │                    29.3.1, a security vulnerability has been detected that
│                       │      │                   allows attackers to bypass authorization plugins (AuthZ).
│                       │      │                   This issue has been patched in version 29.3.1. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-288 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ ghsa  : 3 
│                       │      │                  ├ nvd   : 3 
│                       │      │                  ├ photon: 3 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 8.8 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 8.4 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-34040 
│                       │      │                  ├ [1]: https://docs.docker.com/engine/extend/plugins_authoriz
│                       │      │                  │      ation 
│                       │      │                  ├ [2]: https://github.com/moby/moby 
│                       │      │                  ├ [3]: https://github.com/moby/moby/commit/e89edb19ad7de0407a
│                       │      │                  │      5d31e3111cb01aa10b5a38 
│                       │      │                  ├ [4]: https://github.com/moby/moby/releases/tag/docker-v29.3.1 
│                       │      │                  ├ [5]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │      │                  │      v23v-6jw2-98fq 
│                       │      │                  ├ [6]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │      │                  │      x744-4wpc-v9h2 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-34040 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-34040 
│                       │      ├ PublishedDate   : 2026-03-31T03:15:57.883Z 
│                       │      ╰ LastModifiedDate: 2026-04-03T16:51:28.67Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-41567 
│                       │      ├ VendorIDs        ─ [0]: GHSA-x86f-5xw2-fm2r 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41567 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:fef253e19f87ce0d06a2df3bbfcef93e0394e79e4f1667db2f1f3
│                       │      │                   45f09fe3e28 
│                       │      ├ Title           : Docker: `PUT /containers/{id}/archive` executes container
│                       │      │                   binary on the host 
│                       │      ├ Description     : ## Summary
│                       │      │                   
│                       │      │                   When a user uploads a compressed archive into a container, a
│                       │      │                    malicious image can execute arbitrary code with daemon
│                       │      │                   (host root) privileges.
│                       │      │                   ## Details
│                       │      │                   When handling `PUT /containers/{id}/archive` requests with
│                       │      │                   compressed archives, the daemon decompresses them using
│                       │      │                   external system binaries. Due to incorrect ordering of
│                       │      │                   operations, these binaries are resolved from the container's
│                       │      │                    filesystem rather than the host's. A container image that
│                       │      │                   includes a trojanized decompression binary can achieve code
│                       │      │                   execution as the daemon process whenever a compressed
│                       │      │                   archive is uploaded to that container.
│                       │      │                   The executed binary runs with the daemon's full privileges,
│                       │      │                   including host root UID and unrestricted capabilities.
│                       │      │                   ## Impact
│                       │      │                   Arbitrary code execution as host root, crossing the
│                       │      │                   container-to-host trust boundary.
│                       │      │                   ### Conditions for exploitation
│                       │      │                   - A user must run a container from a malicious image that
│                       │      │                   contains a trojanized decompression binary.
│                       │      │                   - The user must then upload a compressed archive (xz or
│                       │      │                   gzip) into that container, either by piping a compressed
│                       │      │                   archive via `docker cp -` or by calling the `PUT
│                       │      │                   /containers/{id}/archive` API directly with compressed
│                       │      │                   content.
│                       │      │                   ### Not affected
│                       │      │                   Standard `docker cp` usage is **not** affected, because the
│                       │      │                   CLI sends uncompressed tar by default:
│                       │      │                   ```
│                       │      │                   docker cp ./file.txt mycontainer:/file.txt
│                       │      │                   This can only be exploited when explicitly passing a xz or
│                       │      │                   gzip-compressed archive to `docker cp` or the `PUT
│                       │      │                   /containers/{id}/archive` API, for example:
│                       │      │                   cat archive.tar.xz | docker cp - mycontainer:/dir
│                       │      │                   Decompression formats using pure Go implementations (bzip2,
│                       │      │                   zstd, and gzip when the container image does not contain an
│                       │      │                   `unpigz` binary) are also not affected.
│                       │      │                   ## Workarounds
│                       │      │                   - Only run containers from trusted images.
│                       │      │                   - Use authorization plugins to limit access to the `PUT
│                       │      │                   /containers/{id}/archive` endpoint.
│                       │      │                   - Avoid piping compressed archives into containers created
│                       │      │                   from untrusted images. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ VendorSeverity   ─ ghsa: 3 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N 
│                       │      │                         ╰ V3Score : 7.2 
│                       │      ╰ References       ╭ [0]: https://github.com/moby/moby 
│                       │                         ╰ [1]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │                                x86f-5xw2-fm2r 
│                       ├ [12] ╭ VulnerabilityID : CVE-2026-42306 
│                       │      ├ VendorIDs        ─ [0]: GHSA-rg2x-37c3-w2rh 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42306 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:c79a3b64eba4520e5f914b9bb91779294e0c042a9938d570f27ef
│                       │      │                   0e77b79be63 
│                       │      ├ Title           : Docker: Race condition in docker cp allows bind mount
│                       │      │                   redirection to host path 
│                       │      ├ Description     : ## Summary
│                       │      │                   
│                       │      │                   A race condition during `docker cp` mount setup allows a
│                       │      │                   malicious container to redirect a bind mount target to an
│                       │      │                   arbitrary host path, potentially overwriting host files or
│                       │      │                   causing denial of service.
│                       │      │                   ## Details
│                       │      │                   When copying files into a container, the daemon sets up a
│                       │      │                   temporary filesystem view by bind-mounting volumes into a
│                       │      │                   private mount namespace. During this setup, the mount
│                       │      │                   destination is created inside the container root and then a
│                       │      │                   bind mount is attached using the container-relative path
│                       │      │                   resolved to an absolute host path.
│                       │      │                   Between mountpoint creation and the `mount()` syscall, a
│                       │      │                   process running inside the container can replace the
│                       │      │                   destination (or a parent path component) with a symlink
│                       │      │                   pointing to an arbitrary location on the host. The `mount()`
│                       │      │                    syscall follows the symlink, causing the volume to be
│                       │      │                   bind-mounted onto an arbitrary host path instead of the
│                       │      │                   intended container path.
│                       │      │                   ## Impact
│                       │      │                   A malicious container can redirect a volume bind mount to an
│                       │      │                    arbitrary host path. The impact depends on the volume
│                       │      │                   content and mount options:
│                       │      │                   - If the volume is writable, arbitrary host files at the
│                       │      │                   redirected path could be overwritten with the volume's
│                       │      │                   contents.
│                       │      │                   - If the volume is read-only, the host path is masked by the
│                       │      │                    mount for the duration of the operation, causing denial of
│                       │      │                   service.
│                       │      │                   - In all cases the mount is temporary (torn down after the
│                       │      │                   `docker cp` completes), but the effects of any writes
│                       │      │                   persist.
│                       │      │                   ### Conditions for exploitation
│                       │      │                   - A container must have at least one volume mount.
│                       │      │                   - A process inside the container must be able to rapidly
│                       │      │                   create and swap symlinks at the volume mount destination
│                       │      │                   path.
│                       │      │                   - An operator must initiate a `docker cp` into that
│                       │      │                   container, or call the `PUT /containers/{id}/archive` or
│                       │      │                   `HEAD /containers/{id}/archive` API endpoints.
│                       │      │                   ### Not affected
│                       │      │                   - Containers that do not have volume mounts are not
│                       │      │                   affected, as the race occurs during volume bind-mount
│                       │      │                   setup.
│                       │      │                   ## Workarounds
│                       │      │                   - Only run containers from trusted images.
│                       │      │                   - Avoid using `docker cp` with untrusted running
│                       │      │                   containers.
│                       │      │                   - Use authorization plugins to restrict access to the
│                       │      │                   archive API endpoints (`PUT /containers/{id}/archive`, `HEAD
│                       │      │                    /containers/{id}/archive`). 
│                       │      ├ Severity        : HIGH 
│                       │      ├ VendorSeverity   ─ ghsa: 3 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:H 
│                       │      │                         ╰ V3Score : 7.2 
│                       │      ╰ References       ╭ [0]: https://github.com/moby/moby 
│                       │                         ╰ [1]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │                                rg2x-37c3-w2rh 
│                       ├ [13] ╭ VulnerabilityID : CVE-2026-33997 
│                       │      ├ VendorIDs        ─ [0]: GHSA-pxq6-2prw-chj9 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ FixedVersion    : 29.3.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33997 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ff631c2d113746e01579bc7620a4ed88dcda58aa96c0402854b68
│                       │      │                   f70965cad33 
│                       │      ├ Title           : moby: docker: github.com/moby/moby: Moby: Privilege
│                       │      │                   validation bypass during plugin installation 
│                       │      ├ Description     : Moby is an open source container framework. Prior to version
│                       │      │                    29.3.1, a security vulnerability has been detected that
│                       │      │                   allows plugins privilege validation to be bypassed during
│                       │      │                   docker plugin install. Due to an error in the daemon's
│                       │      │                   privilege comparison logic, the daemon may incorrectly
│                       │      │                   accept a privilege set that differs from the one approved by
│                       │      │                    the user. Plugins that request exactly one privilege are
│                       │      │                   also affected, because no comparison is performed at all.
│                       │      │                   This issue has been patched in version 29.3.1. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-193 
│                       │      ├ VendorSeverity   ╭ amazon: 2 
│                       │      │                  ├ ghsa  : 2 
│                       │      │                  ├ nvd   : 3 
│                       │      │                  ├ photon: 3 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.8 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 8.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 8.4 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33997 
│                       │      │                  ├ [1]: https://docs.docker.com/engine/extend/legacy_plugins 
│                       │      │                  ├ [2]: https://github.com/moby/moby 
│                       │      │                  ├ [3]: https://github.com/moby/moby/commit/f4d6f25bf0c3fa12d4
│                       │      │                  │      968320a45685947756a22a 
│                       │      │                  ├ [4]: https://github.com/moby/moby/releases/tag/docker-v29.3.1 
│                       │      │                  ├ [5]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │      │                  │      pxq6-2prw-chj9 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-33997 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-33997 
│                       │      ├ PublishedDate   : 2026-03-31T03:15:57.523Z 
│                       │      ╰ LastModifiedDate: 2026-04-03T17:23:21.307Z 
│                       ├ [14] ╭ VulnerabilityID : CVE-2026-41568 
│                       │      ├ VendorIDs        ─ [0]: GHSA-vp62-88p7-qqf5 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41568 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:a00f7763ec4d0e38c4c8440c7c32aba513ae4b01a4f9f4b065ab2
│                       │      │                   ce7d4cb859f 
│                       │      ├ Title           : Docker: Race condition in docker cp allows creation of
│                       │      │                   arbitrary empty files on the host via symlink swap 
│                       │      ├ Description     : ## Summary
│                       │      │                   
│                       │      │                   A race condition during `docker cp` mount setup allows a
│                       │      │                   malicious container to create empty files or directories at
│                       │      │                   arbitrary absolute paths on the host filesystem.
│                       │      │                   This advisory covers the race during mountpoint creation.
│                       │      │                   The related race during the subsequent mount syscall is
│                       │      │                   tracked in GHSA-rg2x-37c3-w2rh
│                       │      │                   ## Details
│                       │      │                   When copying files into a container, the daemon sets up a
│                       │      │                   temporary filesystem view by bind-mounting volumes into a
│                       │      │                   private mount namespace. During this setup, the mount
│                       │      │                   destination path is first resolved within the container's
│                       │      │                   root filesystem using `GetResourcePath`, and then used to
│                       │      │                   create the mountpoint (file or directory) if it does not
│                       │      │                   already exist via `createIfNotExists`.
│                       │      │                   Between path resolution and mountpoint creation, a process
│                       │      │                   running inside the container can swap a path component for a
│                       │      │                    symlink pointing to an arbitrary location on the host.
│                       │      │                   Because `createIfNotExists` operates on the already-resolved
│                       │      │                    absolute path using standard `os.MkdirAll` and
│                       │      │                   `os.OpenFile` — which follow symlinks in intermediate path
│                       │      │                   components — the symlink is followed and the file or
│                       │      │                   directory is created outside the container root filesystem,
│                       │      │                   as root.
│                       │      │                   ## Impact
│                       │      │                   A malicious container can create empty files or directories
│                       │      │                   at arbitrary absolute paths on the host filesystem, running
│                       │      │                   as root. This enables persistent denial of service — for
│                       │      │                   example:
│                       │      │                   - Converting `/etc/docker/daemon.json` into a directory
│                       │      │                   prevents the daemon from restarting
│                       │      │                   - Creating `/etc/nologin` prevents user logins
│                       │      │                   - Overwriting critical system paths with empty files can
│                       │      │                   break host services
│                       │      │                   The container does not gain read or write access to existing
│                       │      │                    host files — only the ability to create new empty files or
│                       │      │                   directories at chosen paths.
│                       │      │                   ### Conditions for exploitation
│                       │      │                   - A container must be running with a process that can
│                       │      │                   rapidly create and swap symlinks at a volume mount
│                       │      │                   destination path.
│                       │      │                   - An operator must initiate a `docker cp` into that
│                       │      │                   container, or call the `PUT /containers/{id}/archive` or
│                       │      │                   `HEAD /containers/{id}/archive` API endpoints.
│                       │      │                   ### Not affected
│                       │      │                   - Containers that do not have volume mounts are not
│                       │      │                   affected, as the race occurs during volume bind-mount
│                       │      │                   setup.
│                       │      │                   ## Patches
│                       │      │                   Mountpoint creation is now scoped to the container root
│                       │      │                   using `os.Root` (Go 1.24+), which refuses to follow symlinks
│                       │      │                    that escape the opened root directory. All filesystem
│                       │      │                   operations in `createIfNotExists` (`MkdirAll`, `OpenFile`)
│                       │      │                   are performed through the `os.Root` handle, so even if a
│                       │      │                   symlink swap occurs after path resolution, the creation
│                       │      │                   stays confined to the container root.
│                       │      │                   ## Workarounds
│                       │      │                   - Only run containers from trusted images.
│                       │      │                   - Avoid using `docker cp` with untrusted running
│                       │      │                   containers.
│                       │      │                   - Use authorization plugins to restrict access to the
│                       │      │                   archive API endpoints (`PUT /containers/{id}/archive`, `HEAD
│                       │      │                    /containers/{id}/archive`). 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:H 
│                       │      │                         ╰ V3Score : 6 
│                       │      ╰ References       ╭ [0]: https://github.com/moby/moby 
│                       │                         ╰ [1]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │                                vp62-88p7-qqf5 
│                       ├ [15] ╭ VulnerabilityID : CVE-2026-33729 
│                       │      ├ VendorIDs        ─ [0]: GHSA-h6c8-cww8-35hf 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.13.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33729 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:eed30662dd67ad047d7ce3c19dc0e8f1bcffaa120b734f4637a30
│                       │      │                   64d2fe5eb3c 
│                       │      ├ Title           : OpenFGA has an Authorization Bypass through cached keys 
│                       │      ├ Description     : OpenFGA is a high-performance and flexible
│                       │      │                   authorization/permission engine built for developers and
│                       │      │                   inspired by Google Zanzibar. In versions prior to 1.13.1,
│                       │      │                   under specific conditions, models using conditions with
│                       │      │                   caching enabled can result in two different check requests
│                       │      │                   producing the same cache key. This can result in OpenFGA
│                       │      │                   reusing an earlier cached result for a different request.
│                       │      │                   Users are affected if the model has relations which rely on
│                       │      │                   condition evaluation andncaching is enabled. OpenFGA v1.13.1
│                       │      │                    contains a patch. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ╭ [0]: CWE-20 
│                       │      │                  ├ [1]: CWE-345 
│                       │      │                  ╰ [2]: CWE-1289 
│                       │      ├ VendorSeverity   ╭ ghsa: 2 
│                       │      │                  ╰ nvd : 4 
│                       │      ├ CVSS             ╭ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI
│                       │      │                  │      │            :N/VA:N/SC:H/SI:H/SA:H 
│                       │      │                  │      ╰ V40Score : 5.8 
│                       │      │                  ╰ nvd  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 
│                       │      │                         ╰ V3Score : 9.8 
│                       │      ├ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │      │                  ├ [1]: https://github.com/openfga/openfga/commit/049b50ccd2cc
│                       │      │                  │      7e163bd897f3d17a7b859ad146f8 
│                       │      │                  ├ [2]: https://github.com/openfga/openfga/releases/tag/v1.13.1 
│                       │      │                  ├ [3]: https://github.com/openfga/openfga/security/advisories
│                       │      │                  │      /GHSA-h6c8-cww8-35hf 
│                       │      │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33729 
│                       │      ├ PublishedDate   : 2026-03-27T01:16:20.367Z 
│                       │      ╰ LastModifiedDate: 2026-04-14T01:04:41.103Z 
│                       ├ [16] ╭ VulnerabilityID : CVE-2026-34972 
│                       │      ├ VendorIDs        ─ [0]: GHSA-jwvj-g8pc-cx45 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.14.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-34972 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:fcff1ab8f67380b12d164b792c96d77a694d2fed0357653c6e441
│                       │      │                   826934417c6 
│                       │      ├ Title           : github.com/openfga/openfga: OpenFGA: Improper policy
│                       │      │                   enforcement via specific BatchCheck calls 
│                       │      ├ Description     : OpenFGA is a high-performance and flexible
│                       │      │                   authorization/permission engine built for developers and
│                       │      │                   inspired by Google Zanzibar. From 1.8.0 to 1.13.1, under
│                       │      │                   specific conditions, BatchCheck calls with multiple checks
│                       │      │                   sent for the same object, relation, and user combination can
│                       │      │                    result in improper policy enforcement. This vulnerability
│                       │      │                   is fixed in 1.14.0. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-863 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 3 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 5 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 8.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 4.2 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-34972 
│                       │      │                  ├ [1]: https://github.com/openfga/openfga 
│                       │      │                  ├ [2]: https://github.com/openfga/openfga/security/advisories
│                       │      │                  │      /GHSA-jwvj-g8pc-cx45 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-34972 
│                       │      │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2026-34972 
│                       │      ├ PublishedDate   : 2026-04-06T21:16:19.997Z 
│                       │      ╰ LastModifiedDate: 2026-04-20T16:55:51.03Z 
│                       ├ [17] ╭ VulnerabilityID : CVE-2026-40293 
│                       │      ├ VendorIDs        ─ [0]: GHSA-68m9-983m-f3v5 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.14.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40293 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:598f12226fe3a731a212b8d82cbd65bfae20a99bf875d801cc4b3
│                       │      │                   00000f619e0 
│                       │      ├ Title           : OpenFGA: github.com/openfga/openfga: OpenFGA: Information
│                       │      │                   disclosure of preshared API key via playground endpoint 
│                       │      ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │      │                   developers. In versions 0.1.4 through 1.13.1, when OpenFGA
│                       │      │                   is configured to use preshared-key authentication with the
│                       │      │                   built-in playground enabled, the local server includes the
│                       │      │                   preshared API key in the HTML response of the /playground
│                       │      │                   endpoint. The /playground endpoint is enabled by default and
│                       │      │                    does not require authentication. It is intended for local
│                       │      │                   development and debugging and is not designed to be exposed
│                       │      │                   to production environments. Only those who run OpenFGA with
│                       │      │                   `--authn-method` preshared, with the playground enabled, and
│                       │      │                    with the playground endpoint accessible beyond localhost or
│                       │      │                    trusted networks are vulnerable. To remediate the issue,
│                       │      │                   users should upgrade to OpenFGA v1.14.0, or disable the
│                       │      │                   playground by running `./openfga run
│                       │      │                   --playground-enabled=false.` 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-200 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-40293 
│                       │      │                  ├ [1]: https://github.com/openfga/openfga 
│                       │      │                  ├ [2]: https://github.com/openfga/openfga/releases/tag/v1.14.0 
│                       │      │                  ├ [3]: https://github.com/openfga/openfga/security/advisories
│                       │      │                  │      /GHSA-68m9-983m-f3v5 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-40293 
│                       │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-40293 
│                       │      ├ PublishedDate   : 2026-04-17T21:16:34.567Z 
│                       │      ╰ LastModifiedDate: 2026-04-27T19:39:47.497Z 
│                       ├ [18] ╭ VulnerabilityID : CVE-2026-41131 
│                       │      ├ VendorIDs        ─ [0]: GHSA-57j5-qwp2-vqp6 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.14.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41131 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:5dee8e9be7edc150128ff3eb3a05fc5c78d3e511ad26a6e351ff9
│                       │      │                   2625f8c3733 
│                       │      ├ Title           : openfga: OpenFGA: Incorrect authorization decisions due to
│                       │      │                   cache key collision 
│                       │      ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │      │                   developers. Prior to version 1.14.1, in specific scenarios,
│                       │      │                   models using conditions with caching enabled can result in
│                       │      │                   two different check requests producing the same cache key.
│                       │      │                   This could result in OpenFGA reusing an earlier cached
│                       │      │                   result for a subsequent request. The preconditions for
│                       │      │                   vulnerability are the model having relations which rely on
│                       │      │                   condition evaluation and the user having caching enabled.
│                       │      │                   OpenFGA v1.14.1 contains a fix. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ╭ [0]: CWE-706 
│                       │      │                  ╰ [1]: CWE-863 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-41131 
│                       │      │                  ├ [1]: https://github.com/openfga/openfga 
│                       │      │                  ├ [2]: https://github.com/openfga/openfga/releases/tag/v1.14.1 
│                       │      │                  ├ [3]: https://github.com/openfga/openfga/security/advisories
│                       │      │                  │      /GHSA-57j5-qwp2-vqp6 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-41131 
│                       │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-41131 
│                       │      ├ PublishedDate   : 2026-04-22T00:16:29.013Z 
│                       │      ╰ LastModifiedDate: 2026-04-24T13:44:37.287Z 
│                       ├ [19] ╭ VulnerabilityID : CVE-2026-42151 
│                       │      ├ VendorIDs        ─ [0]: GHSA-wg65-39gg-5wfj 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42151 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:beba46a1e1e7a2a676336eb77a78733fe628827daf5d0ae3594ee
│                       │      │                   780f8c36c4d 
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
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
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
│                       ├ [20] ╭ VulnerabilityID : CVE-2026-42154 
│                       │      ├ VendorIDs        ─ [0]: GHSA-8rm2-7qqf-34qm 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42154 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:8b36ef441e8c8b1cf0ae502d24592c34400e1552b12e2d65a24eb
│                       │      │                   4d7962ba726 
│                       │      ├ Title           : github.com/prometheus/prometheus: Prometheus: Denial of
│                       │      │                   Service via uncontrolled memory allocation in remote read
│                       │      │                   endpoint 
│                       │      ├ Description     : Prometheus is an open-source monitoring system and time
│                       │      │                   series database. Prior to versions 3.5.3 and 3.11.3, the
│                       │      │                   remote read endpoint (/api/v1/read) does not validate the
│                       │      │                   declared decoded length in a snappy-compressed request body
│                       │      │                   before allocating memory. An unauthenticated attacker can
│                       │      │                   send a small payload that causes a huge heap allocation per
│                       │      │                   request. Under concurrent load this can exhaust available
│                       │      │                   memory and crash the Prometheus process. This issue has been
│                       │      │                    patched in versions 3.5.3 and 3.11.3. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-400 
│                       │      │                  ╰ [1]: CWE-789 
│                       │      ├ VendorSeverity   ╭ azure  : 2 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42154 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/pull/18584 
│                       │      │                  ├ [3]: https://github.com/prometheus/prometheus/pull/18585 
│                       │      │                  ├ [4]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.11.3 
│                       │      │                  ├ [5]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.5.3 
│                       │      │                  ├ [6]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-8rm2-7qqf-34qm 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42154 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-42154 
│                       │      ├ PublishedDate   : 2026-05-04T19:16:04.397Z 
│                       │      ╰ LastModifiedDate: 2026-05-11T17:22:42.86Z 
│                       ├ [21] ╭ VulnerabilityID : CVE-2026-40179 
│                       │      ├ VendorIDs        ─ [0]: GHSA-vffh-x6r8-xx99 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.2-0.20260410083055-07c6232d159b 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40179 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:5584211adb1b5b86bfa4288438f38e10cf47b949c767a56b554e6
│                       │      │                   91c874c4f9d 
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
│                       ├ [22] ╭ VulnerabilityID : CVE-2026-44903 
│                       │      ├ VendorIDs        ─ [0]: GHSA-fw8g-cg8f-9j28 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-44903 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:55a7ab78c693cb2aac94109ccf15e1556321a2357bcba9876e03a
│                       │      │                   dad5842ad9a 
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
│                       │      │                  ╰ ghsa   : 2 
│                       │      ├ CVSS             ─ bitnami ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N
│                       │      │                            │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                            ╰ V40Score : 5.1 
│                       │      ├ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus/commit/38f23b
│                       │      │                  │      9075ced1de2b82d2dad8b2bebb1ecd5b7d 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-fw8g-cg8f-9j28 
│                       │      │                  ╰ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-44903 
│                       │      ├ PublishedDate   : 2026-05-26T22:16:43.01Z 
│                       │      ╰ LastModifiedDate: 2026-05-29T16:19:35.753Z 
│                       ├ [23] ╭ VulnerabilityID : CVE-2026-39882 
│                       │      ├ VendorIDs        ─ [0]: GHSA-w8rr-5gcm-pp58 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp@
│                       │      │                   v0.12.2 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                       │      │                  │       lplog/otlploghttp@v0.12.2 
│                       │      │                  ╰ UID : aa0d3c7cd3dd989b 
│                       │      ├ InstalledVersion: v0.12.2 
│                       │      ├ FixedVersion    : 0.19.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:5def8ca26416bcf878dd43c1bdf83ae88be1e723874bf1637f042
│                       │      │                   ec582a3a6aa 
│                       │      ├ Title           : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   Prior to 1 ... 
│                       │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   Prior to 1.43.0, the otlp HTTP exporters
│                       │      │                   (traces/metrics/logs) read the full HTTP response body into
│                       │      │                   an in-memory bytes.Buffer without a size cap. This is
│                       │      │                   exploitable for memory exhaustion when the configured
│                       │      │                   collector endpoint is attacker-controlled (or a network
│                       │      │                   attacker can mitm the exporter connection). This
│                       │      │                   vulnerability is fixed in 1.43.0. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-789 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ ghsa  : 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H 
│                       │      │                         ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: http://github.com/open-telemetry/opentelemetry-go/rele
│                       │      │                  │      ases/tag/v1.43.0 
│                       │      │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                       │      │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/pul
│                       │      │                  │      l/8108 
│                       │      │                  ├ [3]: https://github.com/open-telemetry/opentelemetry-go/sec
│                       │      │                  │      urity/advisories/GHSA-w8rr-5gcm-pp58 
│                       │      │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39882 
│                       │      ├ PublishedDate   : 2026-04-08T21:17:00.547Z 
│                       │      ╰ LastModifiedDate: 2026-04-09T18:39:55.73Z 
│                       ├ [24] ╭ VulnerabilityID : CVE-2026-39882 
│                       │      ├ VendorIDs        ─ [0]: GHSA-w8rr-5gcm-pp58 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetri
│                       │      │                   chttp@v1.39.0 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetri
│                       │      │                   chttp 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                       │      │                  │       lpmetric/otlpmetrichttp@v1.39.0 
│                       │      │                  ╰ UID : 27eb081b2e4e79f 
│                       │      ├ InstalledVersion: v1.39.0 
│                       │      ├ FixedVersion    : 1.43.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:f59767ef67b3be41b843382e749aa3fc9ee67daec3a60a3831375
│                       │      │                   6231db9d807 
│                       │      ├ Title           : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   Prior to 1 ... 
│                       │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   Prior to 1.43.0, the otlp HTTP exporters
│                       │      │                   (traces/metrics/logs) read the full HTTP response body into
│                       │      │                   an in-memory bytes.Buffer without a size cap. This is
│                       │      │                   exploitable for memory exhaustion when the configured
│                       │      │                   collector endpoint is attacker-controlled (or a network
│                       │      │                   attacker can mitm the exporter connection). This
│                       │      │                   vulnerability is fixed in 1.43.0. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-789 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ ghsa  : 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H 
│                       │      │                         ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: http://github.com/open-telemetry/opentelemetry-go/rele
│                       │      │                  │      ases/tag/v1.43.0 
│                       │      │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                       │      │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/pul
│                       │      │                  │      l/8108 
│                       │      │                  ├ [3]: https://github.com/open-telemetry/opentelemetry-go/sec
│                       │      │                  │      urity/advisories/GHSA-w8rr-5gcm-pp58 
│                       │      │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39882 
│                       │      ├ PublishedDate   : 2026-04-08T21:17:00.547Z 
│                       │      ╰ LastModifiedDate: 2026-04-09T18:39:55.73Z 
│                       ├ [25] ╭ VulnerabilityID : CVE-2026-39882 
│                       │      ├ VendorIDs        ─ [0]: GHSA-w8rr-5gcm-pp58 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceh
│                       │      │                   ttp@v1.40.0 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceh
│                       │      │                   ttp 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                       │      │                  │       lptrace/otlptracehttp@v1.40.0 
│                       │      │                  ╰ UID : 1def01412f951a52 
│                       │      ├ InstalledVersion: v1.40.0 
│                       │      ├ FixedVersion    : 1.43.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:bd46e8fdcd857a0cf9c5aaea84632c5c354ab9b43eb8c0944f828
│                       │      │                   c478e4d64b4 
│                       │      ├ Title           : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   Prior to 1 ... 
│                       │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   Prior to 1.43.0, the otlp HTTP exporters
│                       │      │                   (traces/metrics/logs) read the full HTTP response body into
│                       │      │                   an in-memory bytes.Buffer without a size cap. This is
│                       │      │                   exploitable for memory exhaustion when the configured
│                       │      │                   collector endpoint is attacker-controlled (or a network
│                       │      │                   attacker can mitm the exporter connection). This
│                       │      │                   vulnerability is fixed in 1.43.0. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-789 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ ghsa  : 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H 
│                       │      │                         ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: http://github.com/open-telemetry/opentelemetry-go/rele
│                       │      │                  │      ases/tag/v1.43.0 
│                       │      │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                       │      │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/pul
│                       │      │                  │      l/8108 
│                       │      │                  ├ [3]: https://github.com/open-telemetry/opentelemetry-go/sec
│                       │      │                  │      urity/advisories/GHSA-w8rr-5gcm-pp58 
│                       │      │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39882 
│                       │      ├ PublishedDate   : 2026-04-08T21:17:00.547Z 
│                       │      ╰ LastModifiedDate: 2026-04-09T18:39:55.73Z 
│                       ├ [26] ╭ VulnerabilityID : CVE-2026-39883 
│                       │      ├ VendorIDs        ─ [0]: GHSA-hfvc-g4fc-pqhx 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.42.0 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.42.0 
│                       │      │                  ╰ UID : 9f0357f06426b992 
│                       │      ├ InstalledVersion: v1.42.0 
│                       │      ├ FixedVersion    : 1.43.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:0fe4d832e1662957d539890fa663ac8f623094f9c11878c78326b
│                       │      │                   07535620774 
│                       │      ├ Title           : opentelemetry-go: BSD kenv command not using absolute path
│                       │      │                   enables PATH hijacking 
│                       │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
│                       │      │                   From 1.15.0 to 1.42.0, the fix for CVE-2026-24051 changed
│                       │      │                   the Darwin ioreg command to use an absolute path but left
│                       │      │                   the BSD kenv command using a bare name, allowing the same
│                       │      │                   PATH hijacking attack on BSD and Solaris platforms. This
│                       │      │                   vulnerability is fixed in 1.43.0. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-426 
│                       │      ├ VendorSeverity   ╭ ghsa: 3 
│                       │      │                  ╰ nvd : 3 
│                       │      ├ CVSS             ╭ ghsa ╭ V40Vector: CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI
│                       │      │                  │      │            :H/VA:H/SC:N/SI:N/SA:N 
│                       │      │                  │      ╰ V40Score : 7.3 
│                       │      │                  ╰ nvd  ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H 
│                       │      │                         ╰ V3Score : 7 
│                       │      ├ References       ╭ [0]: http://github.com/open-telemetry/opentelemetry-go/rele
│                       │      │                  │      ases/tag/v1.43.0 
│                       │      │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
│                       │      │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/sec
│                       │      │                  │      urity/advisories/GHSA-hfvc-g4fc-pqhx 
│                       │      │                  ╰ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39883 
│                       │      ├ PublishedDate   : 2026-04-08T21:17:00.697Z 
│                       │      ╰ LastModifiedDate: 2026-04-10T21:16:27.12Z 
│                       ├ [27] ╭ VulnerabilityID : CVE-2026-33811 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4981 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:26c0b7d14f70793ac2e718cbb3690844ef811416a1dc38f9bf064
│                       │      │                   04209ff08cc 
│                       │      ├ Title           : net: golang: Go net package: Denial of Service via long
│                       │      │                   CNAME response in LookupCNAME 
│                       │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
│                       │      │                   long CNAME response can trigger a double-free of C memory
│                       │      │                   and a crash. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-415 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ├ nvd    : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33811 
│                       │      │                  ├ [1]: https://go.dev/cl/767860 
│                       │      │                  ├ [2]: https://go.dev/issue/78803 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4981 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
│                       │      ╰ LastModifiedDate: 2026-05-12T20:23:02.333Z 
│                       ├ [28] ╭ VulnerabilityID : CVE-2026-33814 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4918 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:7d1658e473c4251a9762c9f21d1be31a76fef286189269b2c6bfd
│                       │      │                   06044897a55 
│                       │      ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │      │                    an infini ... 
│                       │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │      │                    an infinite loop of writing CONTINUATION frames if it
│                       │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-835 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ├ azure  : 2 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ├ nvd    : 3 
│                       │      │                  ╰ ubuntu : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://github.com/golang/go/issues/78476 
│                       │      │                  ├ [1]: https://go-review.googlesource.com/c/go/+/761581 
│                       │      │                  ├ [2]: https://go-review.googlesource.com/c/net/+/761640 
│                       │      │                  ├ [3]: https://go.dev/cl/761581 
│                       │      │                  ├ [4]: https://go.dev/cl/761640 
│                       │      │                  ├ [5]: https://go.dev/issue/78476 
│                       │      │                  ├ [6]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
│                       │      │                  ├ [8]: https://pkg.go.dev/vuln/GO-2026-4918 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T14:41:59.52Z 
│                       ├ [29] ╭ VulnerabilityID : CVE-2026-39820 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4986 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4b81c73733e99f6814d57619deef8fd9493d2e5ef9907c4824e20
│                       │      │                   32416e0dec5 
│                       │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │      │                    and Parse ... 
│                       │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │      │                    and ParseDate were able to trigger excessive CPU exhaustion
│                       │      │                    and memory allocations. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ╰ nvd    : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/759940 
│                       │      │                  ├ [1]: https://go.dev/issue/78566 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4986 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T15:10:58.65Z 
│                       ├ [30] ╭ VulnerabilityID : CVE-2026-39823 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4982 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4d09890c472f87ee83179ae5342d3f78b52ac0e8fc49fc4d6526e
│                       │      │                   4cd0acf6ac0 
│                       │      ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │      │                   correctly  ... 
│                       │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │      │                   correctly escaped inside of a <meta> tag's <content>
│                       │      │                   attribute. If the URL content were to insert ASCII
│                       │      │                   whitespaces around the '=' rune inside of the <content>
│                       │      │                   attribute, the escaper would fail to similarly escape it,
│                       │      │                   leading to XSS. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/769920 
│                       │      │                  ├ [1]: https://go.dev/issue/78913 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39823 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4982 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:43.29Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T16:58:45.697Z 
│                       ├ [31] ╭ VulnerabilityID : CVE-2026-39825 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4976 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:d7aeead605b30334fc749eef599b0b012709ab376a52affcb4391
│                       │      │                   6f14b866c87 
│                       │      ├ Title           : ReverseProxy can forward queries containing parameters not
│                       │      │                   visible to  ... 
│                       │      ├ Description     : ReverseProxy can forward queries containing parameters not
│                       │      │                   visible to Rewrite functions. When used with a Rewrite
│                       │      │                   function, or a Director function which parses query
│                       │      │                   parameters, ReverseProxy sanitizes the forwarded request to
│                       │      │                   remove query parameters which are not parsed by
│                       │      │                   url.ParseQuery. ReverseProxy does not take ParseQuery's
│                       │      │                   limit on the total number of query parameters (controlled by
│                       │      │                    GODEBUG=urlmaxqueryparams=N) into account. This can permit
│                       │      │                   ReverseProxy to forward a request containing a query
│                       │      │                   parameter that is not visible to the Rewrite function. For
│                       │      │                   example, the query "a1=x&a2=x&...&a10000=x&hidden=y" can
│                       │      │                   forward the parameter "hidden=y" while hiding it from the
│                       │      │                   proxy's Rewrite function. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/770541 
│                       │      │                  ├ [1]: https://go.dev/issue/78948 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39825 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4976 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:43.39Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T16:58:56.39Z 
│                       ├ [32] ╭ VulnerabilityID : CVE-2026-39826 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4980 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:16eaea8f771035ea15df6011db7c899e1eccb4ccd41dda4ba19bb
│                       │      │                   3151e918ce4 
│                       │      ├ Title           : If a trusted template author were to write a <script> tag
│                       │      │                   containing a ... 
│                       │      ├ Description     : If a trusted template author were to write a <script> tag
│                       │      │                   containing an empty 'type' attribute or a 'type' attribute
│                       │      │                   with an ASCII whitespace, the execution of the template
│                       │      │                   would incorrectly escape any data passed into the <script>
│                       │      │                   block. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-116 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/771180 
│                       │      │                  ├ [1]: https://go.dev/issue/78981 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4980 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T16:59:07.48Z 
│                       ├ [33] ╭ VulnerabilityID : CVE-2026-39836 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4971 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:e8358e56dcfbb724eaff2d2c065548d03f00bd80ade8b2099c093
│                       │      │                   83d8c0df4db 
│                       │      ├ Title           : Panic in Dial and LookupPort when handling NUL byte on
│                       │      │                   Windows in net 
│                       │      ├ Description     : The Dial and LookupPort functions panic on Windows when
│                       │      │                   provided with an input containing a NUL (0). 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-476 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ nvd    : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/775320 
│                       │      │                  ├ [1]: https://go.dev/issue/79006 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39836 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4971 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:43.593Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T15:11:10.31Z 
│                       ├ [34] ╭ VulnerabilityID : CVE-2026-42499 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4977 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:a2980282820cb2a817744483baf24f4bf535d6a2940a984385301
│                       │      │                   d75be1f1222 
│                       │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
│                       │      │                   when parsing ... 
│                       │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
│                       │      │                   when parsing an email address according to RFC 5322. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 3 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/771520 
│                       │      │                  ├ [1]: https://go.dev/issue/78987 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4977 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T16:59:17.563Z 
│                       ├ [35] ╭ VulnerabilityID : CVE-2026-27145 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:3adce4c8ff546e4d06dd0342f11e0612f75c592f3d05fec338ff5
│                       │      │                   d51f8213598 
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
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │      │                  ├ [1]: https://go.dev/issue/79694 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-06-02T23:16:35.57Z 
│                       ├ [36] ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                       │      │                  │         84e4c304a53b964ae1af 
│                       │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                       │      │                            af5b9fb7eae16eed715f 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:384d801b0c9c2b8c51623229dae3a3661ca998cb451ed0c02ca8b
│                       │      │                   ea47122de61 
│                       │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid enc ... 
│                       │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid encoded-words can consume excessive CPU. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │      │                  ├ [1]: https://go.dev/issue/79217 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │      ╰ LastModifiedDate: 2026-06-03T16:16:30.157Z 
│                       ╰ [37] ╭ VulnerabilityID : CVE-2026-42507 
│                              ├ VendorIDs        ─ [0]: GO-2026-5039 
│                              ├ PkgID           : stdlib@v1.25.9 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                              │                  ╰ UID : 2f9d47014fd0da0e 
│                              ├ InstalledVersion: v1.25.9 
│                              ├ FixedVersion    : 1.25.11, 1.26.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
│                              │                  │         84e4c304a53b964ae1af 
│                              │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
│                              │                            af5b9fb7eae16eed715f 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:5ea339d3862633bcd7d8520b601a1b0ac8088180c95bd3351e7f5
│                              │                   ea751a05b90 
│                              ├ Title           : When returning errors, functions in the net/textproto
│                              │                   package would in ... 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : UNKNOWN 
│                              ├ References       ╭ [0]: https://go.dev/cl/777060 
│                              │                  ├ [1]: https://go.dev/issue/79346 
│                              │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                              │                  │      cKw 
│                              │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                              ╰ LastModifiedDate: 2026-06-03T20:16:20.65Z 
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
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:1c34fde930db3113679e45d2419298ea062e9757f6ef9e87ca366
                        │      │                   4ee821ef847 
                        │      ├ Title           : net: golang: Go net package: Denial of Service via long
                        │      │                   CNAME response in LookupCNAME 
                        │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME response can trigger a double-free of C memory
                        │      │                   and a crash. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-415 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ bitnami: 3 
                        │      │                  ├ nvd    : 3 
                        │      │                  ╰ redhat : 3 
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
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
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
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:bb0337433cd879ef914b0b3282c4bff5c03c2f0c1701956d480e8
                        │      │                   8373a92949e 
                        │      ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infini ... 
                        │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infinite loop of writing CONTINUATION frames if it
                        │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ azure  : 2 
                        │      │                  ├ bitnami: 3 
                        │      │                  ├ nvd    : 3 
                        │      │                  ╰ ubuntu : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://github.com/golang/go/issues/78476 
                        │      │                  ├ [1]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [2]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [3]: https://go.dev/cl/761581 
                        │      │                  ├ [4]: https://go.dev/cl/761640 
                        │      │                  ├ [5]: https://go.dev/issue/78476 
                        │      │                  ├ [6]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [8]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
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
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:93a9f50ad352904bc9508b00f998d63bee0be3671445b02df86a8
                        │      │                   47e3ebbc006 
                        │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and Parse ... 
                        │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and ParseDate were able to trigger excessive CPU exhaustion
                        │      │                    and memory allocations. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ bitnami: 3 
                        │      │                  ╰ nvd    : 3 
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
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4986 
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
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:9ecb65357d3e28d65f50f5d04505e5934c3f611ac35ca87fc1819
                        │      │                   1fa96c18fd1 
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
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ╰ bitnami: 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://go.dev/cl/769920 
                        │      │                  ├ [1]: https://go.dev/issue/78913 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39823 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4982 
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
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:09e917d0a9060ed0883a2901ff07c077da11039666f295c423db9
                        │      │                   3a8fd186550 
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
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ╰ bitnami: 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://go.dev/cl/770541 
                        │      │                  ├ [1]: https://go.dev/issue/78948 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39825 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4976 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.39Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:58:56.39Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-39826 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4980 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:1e8343d4f48d40c282a7111886b4938e28457ed149a8e7512f851
                        │      │                   ea27e353029 
                        │      ├ Title           : If a trusted template author were to write a <script> tag
                        │      │                   containing a ... 
                        │      ├ Description     : If a trusted template author were to write a <script> tag
                        │      │                   containing an empty 'type' attribute or a 'type' attribute
                        │      │                   with an ASCII whitespace, the execution of the template
                        │      │                   would incorrectly escape any data passed into the <script>
                        │      │                   block. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-116 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ╰ bitnami: 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://go.dev/cl/771180 
                        │      │                  ├ [1]: https://go.dev/issue/78981 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4980 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:59:07.48Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3ff5c362f8d12ee40abb69cf2d918cc1c7ff72781c06e73faf39d
                        │      │                   6e362727874 
                        │      ├ Title           : Panic in Dial and LookupPort when handling NUL byte on
                        │      │                   Windows in net 
                        │      ├ Description     : The Dial and LookupPort functions panic on Windows when
                        │      │                   provided with an input containing a NUL (0). 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-476 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ nvd    : 3 
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
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39836 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4971 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.593Z 
                        │      ╰ LastModifiedDate: 2026-05-13T15:11:10.31Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3a9eda1f66ac075b88ecc4664a35f95ca8277bf1120748662d15d
                        │      │                   b547c60b444 
                        │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing ... 
                        │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing an email address according to RFC 5322. 
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ╰ bitnami: 3 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/771520 
                        │      │                  ├ [1]: https://go.dev/issue/78987 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-05-13T16:59:17.563Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e49d6cfd1b4bf4ec81d99c2cef63f19b5e450d46f76a27f47eb69
                        │      │                   54606c54cb7 
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
                        │      ├ Severity        : UNKNOWN 
                        │      ├ References       ╭ [0]: https://go.dev/cl/783621 
                        │      │                  ├ [1]: https://go.dev/issue/79694 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-06-02T23:16:35.57Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                        │      │                  │         84e4c304a53b964ae1af 
                        │      │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                        │      │                            af5b9fb7eae16eed715f 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c5d7aa8ffe654c8be2532540c6503221ef6f46dc7bec6b60ff036
                        │      │                   20415cef77b 
                        │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid enc ... 
                        │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid encoded-words can consume excessive CPU. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ CweIDs           ─ [0]: CWE-407 
                        │      ├ References       ╭ [0]: https://go.dev/cl/774481 
                        │      │                  ├ [1]: https://go.dev/issue/79217 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5038 
                        │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
                        │      ╰ LastModifiedDate: 2026-06-03T16:16:30.157Z 
                        ╰ [10] ╭ VulnerabilityID : CVE-2026-42507 
                               ├ VendorIDs        ─ [0]: GO-2026-5039 
                               ├ PkgID           : stdlib@v1.26.2 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                               │                  ╰ UID : 83c42d84cdb2ccfe 
                               ├ InstalledVersion: v1.26.2 
                               ├ FixedVersion    : 1.25.11, 1.26.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:1c31db2904ae1d02b19ff30be9618d10ad173c89dc9c
                               │                  │         84e4c304a53b964ae1af 
                               │                  ╰ DiffID: sha256:9e0c0d10daea239511f46e283a63ca11df80344cda1a
                               │                            af5b9fb7eae16eed715f 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:6602e43f1dca9aa9f57a1342c36bf9c98919de49e2bcd83fcf5bc
                               │                   d7f555b42c0 
                               ├ Title           : When returning errors, functions in the net/textproto
                               │                   package would in ... 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : UNKNOWN 
                               ├ References       ╭ [0]: https://go.dev/cl/777060 
                               │                  ├ [1]: https://go.dev/issue/79346 
                               │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                               │                  │      cKw 
                               │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5039 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-06-03T20:16:20.65Z 
```

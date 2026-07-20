```yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.24.0) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target         : Java 
│     ├ Class          : lang-pkgs 
│     ├ Type           : jar 
│     ├ Packages        
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-54515 
│                             ├ VendorIDs        ─ [0]: GHSA-5jmj-h7xm-6q6v 
│                             ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                             ├ PkgPath         : openaf/openaf.jar 
│                             ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                             │                  │       2.22.0 
│                             │                  ╰ UID : c3b2e55f064f8b6 
│                             ├ InstalledVersion: 2.22.0 
│                             ├ FixedVersion    : 3.1.4, 2.18.9, 2.21.5, 2.22.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                             │                  │         7b5687b2443e5cccf74 
│                             │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                             │                            9931ea661da63126f54 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54515 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:77e8fa4e5c20134c29d29bce6bd450d566f5a9c925c1b5cf6a0fe7
│                             │                   ff52967ebd 
│                             ├ Title           : jackson-databind: jackson-databind: Ignored properties can be
│                             │                    unexpectedly modified 
│                             ├ Description     : jackson-databind contains the general-purpose data-binding
│                             │                   functionality and tree-model for Jackson Data Processor. From
│                             │                    2.8.0 until 2.18.9, 2.21.5, and 3.1.4, in
│                             │                   BeanDeserializerBase.createContextual(), per-property
│                             │                   @JsonIgnoreProperties exclusions are applied by
│                             │                   _handleByNameInclusion(), producing a contextual deserializer
│                             │                    whose BeanPropertyMap has the ignored properties removed.
│                             │                   The subsequent per-property case-insensitivity block
│                             │                   (triggered by
│                             │                   @JsonFormat(ACCEPT_CASE_INSENSITIVE_PROPERTIES)) rebuilds
│                             │                   from this._beanProperties (the original, unfiltered map)
│                             │                   instead of contextual._beanProperties, then overwrites the
│                             │                   filtered map — restoring every property
│                             │                   _handleByNameInclusion had just removed. The ignored property
│                             │                    becomes writable again. This vulnerability is fixed in
│                             │                   2.18.9, 2.21.5, and 3.1.4. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-915 
│                             ├ VendorSeverity   ╭ ghsa  : 2 
│                             │                  ╰ redhat: 2 
│                             ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                             │                  │        │           A:N 
│                             │                  │        ╰ V3Score : 5.3 
│                             │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                             │                           │           A:N 
│                             │                           ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54515 
│                             │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                             │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/0e
│                             │                  │      1b0b211f7a53baa62ba2f4c9bd006c7bf4d5fa 
│                             │                  ├ [3]: https://github.com/FasterXML/jackson-databind/issues/5962 
│                             │                  ├ [4]: https://github.com/FasterXML/jackson-databind/issues/5964 
│                             │                  ├ [5]: https://github.com/FasterXML/jackson-databind/security/
│                             │                  │      advisories/GHSA-5jmj-h7xm-6q6v 
│                             │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-54515 
│                             │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-54515 
│                             ├ PublishedDate   : 2026-06-23T21:17:02.597Z 
│                             ╰ LastModifiedDate: 2026-06-29T13:38:59.057Z 
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
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : 2b26bad30f661468 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:f15a861d4f7f7e017de7d8f12d7a2bb792ff6aa808aa2ffd129c1c
│                       │     │                   3776a58af1 
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
│                       │     │                  ╰ UID : f924e5a57022ddfb 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ce8a86b3636178b8046d0027cf36f940047ce9300b8091f8be5607
│                       │     │                   f64d5202ce 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic in
│                       │     │                   golang.org/x/net/dns/dnsmessage 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/cl/786345 
│                       │                        ├ [1]: https://go.dev/issue/79795 
│                       │                        ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                             ├ VendorIDs        ─ [0]: GO-2026-5970 
│                             ├ PkgID           : golang.org/x/text@v0.38.0 
│                             ├ PkgName         : golang.org/x/text 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.38.0 
│                             │                  ╰ UID : cc7844dfa03c0f59 
│                             ├ InstalledVersion: v0.38.0 
│                             ├ FixedVersion    : 0.39.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                             │                  │         7b5687b2443e5cccf74 
│                             │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                             │                            9931ea661da63126f54 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:1dfe503bd6020998cbe2af25023ee12af71b7bf4ba93a61e3f731a
│                             │                   bd953c9f55 
│                             ├ Title           : Infinite loop on invalid input in golang.org/x/text 
│                             ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                             │                   containing invalid UTF-8 bytes. 
│                             ├ Severity        : UNKNOWN 
│                             ╰ References       ╭ [0]: https://go.dev/cl/794100 
│                                                ├ [1]: https://go.dev/issue/80142 
│                                                ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5970 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : e59a4f7d0abf5558 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:721a07dbf439d22d87524a28d2c7515d2d04ecd3a31486db6c9fdb
│                       │     │                   0959bb4b78 
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
│                       │     │                  ╰ UID : f9566a120c579957 
│                       │     ├ InstalledVersion: v0.55.0 
│                       │     ├ FixedVersion    : 0.56.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:7beffc56bb7c0b733c36225913bb6b0cf5e2b6ada85107fea92cf6
│                       │     │                   6e40e54ae1 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic in
│                       │     │                   golang.org/x/net/dns/dnsmessage 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/cl/786345 
│                       │                        ├ [1]: https://go.dev/issue/79795 
│                       │                        ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                             ├ VendorIDs        ─ [0]: GO-2026-5970 
│                             ├ PkgID           : golang.org/x/text@v0.38.0 
│                             ├ PkgName         : golang.org/x/text 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.38.0 
│                             │                  ╰ UID : 9948c7061f564f61 
│                             ├ InstalledVersion: v0.38.0 
│                             ├ FixedVersion    : 0.39.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                             │                  │         7b5687b2443e5cccf74 
│                             │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                             │                            9931ea661da63126f54 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:95dead2d41b9cac4d22d2522e24e3c7940ab05a2b2371a2a94be5c
│                             │                   d04552b772 
│                             ├ Title           : Infinite loop on invalid input in golang.org/x/text 
│                             ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                             │                   containing invalid UTF-8 bytes. 
│                             ├ Severity        : UNKNOWN 
│                             ╰ References       ╭ [0]: https://go.dev/cl/794100 
│                                                ├ [1]: https://go.dev/issue/80142 
│                                                ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5970 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-21728 
│                       │     ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ PkgName         : github.com/grafana/tempo 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.202604271
│                       │     │                  │       12133-525d1bab07e0 
│                       │     │                  ╰ UID : 18b157406ef90a65 
│                       │     ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:6b0daac831da80a3d275daab4bb4f5df3afc410501fd06d4d235f1
│                       │     │                   a814af410c 
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
│                       │     ╰ LastModifiedDate: 2026-07-15T02:18:31.26Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-28377 
│                       │     ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │     ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ PkgName         : github.com/grafana/tempo 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.202604271
│                       │     │                  │       12133-525d1bab07e0 
│                       │     │                  ╰ UID : 18b157406ef90a65 
│                       │     ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │     ├ FixedVersion    : 2.10.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:b9ef150d3e63f18aa037a176c25e8dd9a8e712e4b84b680f338143
│                       │     │                   94d25e1839 
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
│                       │     │                  ├ [1]: https://github.com/grafana/tempo 
│                       │     │                  ├ [2]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b6
│                       │     │                  │      7498b662b85a148698b4afd/CHANGELOG.md?plain=1#L135 
│                       │     │                  ├ [3]: https://github.com/grafana/tempo/commit/bb8ca663db34a09
│                       │     │                  │      80c9758b40d918fda3b4dbec3 
│                       │     │                  ├ [4]: https://grafana.com/security/security-advisories/cve-20
│                       │     │                  │      26-28377 
│                       │     │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-28377 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-28377 
│                       │     ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                       │     ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-48096 
│                       │     ├ VendorIDs        ─ [0]: GHSA-8396-jffm-qx4w 
│                       │     ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │     ├ PkgName         : github.com/openfga/openfga 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │     │                  ╰ UID : d9f7c327b4e77cd7 
│                       │     ├ InstalledVersion: v1.14.2 
│                       │     ├ FixedVersion    : 1.16.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-48096 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:55e2b3257e5ae901ae54607844dc65b62cb186f15df3648da66f58
│                       │     │                   9152886bc8 
│                       │     ├ Title           : OpenFGA: OpenFGA: Incorrect authorization due to cache key
│                       │     │                   collision in iterator caching 
│                       │     ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │     │                   developers. Prior to version 1.16.0, when iterator caching is
│                       │     │                    enabled, two distinct check requests can produce the same
│                       │     │                   cache key, leading to OpenFGA reusing an earlier cached
│                       │     │                   result for a subsequent request. This issue has been patched
│                       │     │                   in version 1.16.0. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ╭ [0]: CWE-345 
│                       │     │                  ╰ [1]: CWE-668 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ├ nvd   : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/
│                       │     │                  │        │           A:L 
│                       │     │                  │        ╰ V3Score : 5 
│                       │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/
│                       │     │                           │           A:L 
│                       │     │                           ╰ V3Score : 5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-48096 
│                       │     │                  ├ [1]: https://github.com/openfga/openfga 
│                       │     │                  ├ [2]: https://github.com/openfga/openfga/releases/tag/v1.16.0 
│                       │     │                  ├ [3]: https://github.com/openfga/openfga/security/advisories/
│                       │     │                  │      GHSA-8396-jffm-qx4w 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-48096 
│                       │     │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-48096 
│                       │     ├ PublishedDate   : 2026-06-10T16:17:09.397Z 
│                       │     ╰ LastModifiedDate: 2026-06-17T10:54:51.107Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-55689 
│                       │     ├ VendorIDs        ─ [0]: GHSA-hcxc-wf8j-23hv 
│                       │     ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │     ├ PkgName         : github.com/openfga/openfga 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │     │                  ╰ UID : d9f7c327b4e77cd7 
│                       │     ├ InstalledVersion: v1.14.2 
│                       │     ├ FixedVersion    : 1.18.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55689 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:0f228d82148cda4970e039a414026f09622d27ccfe94e77dd2ff35
│                       │     │                   09b9efc50b 
│                       │     ├ Title           : openfga: OpenFGA: OIDC audience validation skipped when
│                       │     │                   --authn-oidc-audience is unset 
│                       │     ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │     │                   developers. Prior to 1.18.0, OpenFGA's OIDC authenticator
│                       │     │                   skipped JWT audience validation when authn.method was set to
│                       │     │                   oidc, authn.oidc.issuer was configured, and
│                       │     │                   authn.oidc.audience was not set, allowing a token minted for
│                       │     │                   an unrelated service by the same identity provider to
│                       │     │                   authenticate to OpenFGA. This issue is fixed in 1.18.0. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-287 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ├ nvd   : 3 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 6.8 
│                       │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 8.1 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 6.8 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-55689 
│                       │     │                  ├ [1]: https://github.com/openfga/helm-ch 
│                       │     │                  ├ [2]: https://github.com/openfga/helm-charts/releases/tag/ope
│                       │     │                  │      nfga-0.3.9 
│                       │     │                  ├ [3]: https://github.com/openfga/openfga 
│                       │     │                  ├ [4]: https://github.com/openfga/openfga/commit/44596773b2e62
│                       │     │                  │      738720ef215bf7fa04352954271 
│                       │     │                  ├ [5]: https://github.com/openfga/openfga/releases/tag/v1.18.0 
│                       │     │                  ├ [6]: https://github.com/openfga/openfga/security/advisories/
│                       │     │                  │      GHSA-hcxc-wf8j-23hv 
│                       │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-55689 
│                       │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-55689 
│                       │     ├ PublishedDate   : 2026-07-09T22:17:06.553Z 
│                       │     ╰ LastModifiedDate: 2026-07-14T01:28:44.147Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-55170 
│                       │     ├ VendorIDs        ─ [0]: GHSA-cf98-j28v-49v6 
│                       │     ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │     ├ PkgName         : github.com/openfga/openfga 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │     │                  ╰ UID : d9f7c327b4e77cd7 
│                       │     ├ InstalledVersion: v1.14.2 
│                       │     ├ FixedVersion    : 1.18.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55170 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:d9a79cb8fb91a82398d9fb81e1183e8bf98b16b6bef3aa701e1781
│                       │     │                   ccc00c3beb 
│                       │     ├ Title           : github.com/openfga/openfga: OpenFGA: Incorrect authorization
│                       │     │                   decisions due to case-insensitive comparisons in MySQL
│                       │     │                   datastore 
│                       │     ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │     │                   developers. Prior to 1.18.0, when MySQL is being used as the
│                       │     │                   datastore and authorization decisions rely on case-sensitive
│                       │     │                   user strings, the tuple, changelog, and authorization_model
│                       │     │                   identifier columns can compare case-distinct values such as
│                       │     │                   user:Alice and user:alice as equivalent, causing two distinct
│                       │     │                    check requests to return the same response. This issue is
│                       │     │                   fixed in 1.18.0. 
│                       │     ├ Severity        : LOW 
│                       │     ├ CweIDs           ─ [0]: CWE-178 
│                       │     ├ VendorSeverity   ╭ ghsa  : 1 
│                       │     │                  ├ nvd   : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/V
│                       │     │                  │        │            I:L/VA:N/SC:L/SI:L/SA:N 
│                       │     │                  │        ╰ V40Score : 2.1 
│                       │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.4 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 5.4 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-55170 
│                       │     │                  ├ [1]: https://github.com/openfga/helm-charts/commit/96d5517a2
│                       │     │                  │      693ff5def451dee7d6b9d1baeb281f8 
│                       │     │                  ├ [2]: https://github.com/openfga/helm-charts/releases/tag/ope
│                       │     │                  │      nfga-0.3.9 
│                       │     │                  ├ [3]: https://github.com/openfga/openfga 
│                       │     │                  ├ [4]: https://github.com/openfga/openfga/commit/a2e0dbefc3e01
│                       │     │                  │      a95c785f81a3563bc6571b08b11 
│                       │     │                  ├ [5]: https://github.com/openfga/openfga/releases/tag/v1.18.0 
│                       │     │                  ├ [6]: https://github.com/openfga/openfga/security/advisories/
│                       │     │                  │      GHSA-cf98-j28v-49v6 
│                       │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-55170 
│                       │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-55170 
│                       │     ├ PublishedDate   : 2026-07-09T22:17:05.937Z 
│                       │     ╰ LastModifiedDate: 2026-07-14T01:22:35.62Z 
│                       ├ [5] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.52.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.52.0 
│                       │     │                  ╰ UID : ed1a6850b8ba8c85 
│                       │     ├ InstalledVersion: v0.52.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ee324b9880133a5fecbced11a7f88fba441c54d8a7fedd64203762
│                       │     │                   18a493e098 
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
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:4fce39e3b2a62962b1c3f07908c64a980015f941a0ab6756338649
│                       │     │                   4d548b3591 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic in
│                       │     │                   golang.org/x/net/dns/dnsmessage 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/cl/786345 
│                       │                        ├ [1]: https://go.dev/issue/79795 
│                       │                        ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.37.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.37.0 
│                       │     │                  ╰ UID : f5591d8a5f651e8f 
│                       │     ├ InstalledVersion: v0.37.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:300965a75d114b292a679799a169c57ec4b3f49ef98ecc517403db
│                       │     │                   e21602ac1e 
│                       │     ├ Title           : Infinite loop on invalid input in golang.org/x/text 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/cl/794100 
│                       │                        ├ [1]: https://go.dev/issue/80142 
│                       │                        ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       ├ [8] ╭ VulnerabilityID : CVE-2026-39822 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │     ├ PkgID           : stdlib@v1.26.4 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.4 
│                       │     │                  ╰ UID : 4a1bba4022867f3b 
│                       │     ├ InstalledVersion: v1.26.4 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6682232e99e70d91e2c9a9a831798fc408922618d6b772fc269cc1
│                       │     │                   178d2b0663 
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
│                       ╰ [9] ╭ VulnerabilityID : CVE-2026-42505 
│                             ├ VendorIDs        ─ [0]: GO-2026-5856 
│                             ├ PkgID           : stdlib@v1.26.4 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.4 
│                             │                  ╰ UID : 4a1bba4022867f3b 
│                             ├ InstalledVersion: v1.26.4 
│                             ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                             │                  │         7b5687b2443e5cccf74 
│                             │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                             │                            9931ea661da63126f54 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:0b33f1eeac04d11e51c8ad4ce17b06302287d8f1088a08802251aa
│                             │                   899ad2eab9 
│                             ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
│                             │                   Encrypted Client Hello 
│                             ├ Description     : Handshakes which used Encrypted Client Hello could be
│                             │                   de-anonymized by a passive network observer due to a
│                             │                   disclosure of pre-shared key identities in the unencrypted
│                             │                   client hello. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-201 
│                             ├ VendorSeverity   ╭ bitnami: 2 
│                             │                  ╰ redhat : 2 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                             │                  │         │           /A:N 
│                             │                  │         ╰ V3Score : 5.3 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42505 
│                             │                  ├ [1]: https://go.dev/cl/775960 
│                             │                  ├ [2]: https://go.dev/issue/79282 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp5Sc 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5856 
│                             │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
│                             ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
│                             ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:40f67f313457683765f30e0b328265704afdc36e4340ff0eab6938
│                       │     │                   1d3b996cb6 
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
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:7700bc19d69246ca2f8e26571dcc2469519151b9068b433b5c6660
│                       │     │                   895fc2dc66 
│                       │     ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic in
│                       │     │                   golang.org/x/net/dns/dnsmessage 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/cl/786345 
│                       │                        ├ [1]: https://go.dev/issue/79795 
│                       │                        ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-56852 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5970 
│                       │     ├ PkgID           : golang.org/x/text@v0.37.0 
│                       │     ├ PkgName         : golang.org/x/text 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.37.0 
│                       │     │                  ╰ UID : 69b4d80ba371f59a 
│                       │     ├ InstalledVersion: v0.37.0 
│                       │     ├ FixedVersion    : 0.39.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:33df64e97c5ac2a6e19a192db8afc6697dddaa24a5ebde43ab1454
│                       │     │                   87b529b199 
│                       │     ├ Title           : Infinite loop on invalid input in golang.org/x/text 
│                       │     ├ Description     : A norm.Iter can enter an infinite loop when handling input
│                       │     │                   containing invalid UTF-8 bytes. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ╰ References       ╭ [0]: https://go.dev/cl/794100 
│                       │                        ├ [1]: https://go.dev/issue/80142 
│                       │                        ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5970 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:0e35718745a69517fff930cf0fbdbca78b0eb3e9a0a3aa93e46f51
│                       │     │                   0bf40eb454 
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
│                       │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29981 
│                       │     │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33574 
│                       │     │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:35832 
│                       │     │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36317 
│                       │     │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │     │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │     │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:38995 
│                       │     │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:39005 
│                       │     │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39573 
│                       │     │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39879 
│                       │     │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:41030 
│                       │     │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41036 
│                       │     │                  ├ [16]: https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │     │                  ├ [17]: https://bugzilla.redhat.com/2445356 
│                       │     │                  ├ [18]: https://bugzilla.redhat.com/2484207 
│                       │     │                  ├ [19]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │     │                  ├ [20]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │     │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-25679 
│                       │     │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-27145 
│                       │     │                  ├ [23]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
│                       │     │                  ├ [24]: https://errata.rockylinux.org/RLSA-2026:36317 
│                       │     │                  ├ [25]: https://go.dev/cl/783621 
│                       │     │                  ├ [26]: https://go.dev/issue/79694 
│                       │     │                  ├ [27]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │     │                  │       cKw 
│                       │     │                  ├ [28]: https://linux.oracle.com/cve/CVE-2026-27145.html 
│                       │     │                  ├ [29]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
│                       │     │                  ├ [30]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ├ [31]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     │                  ├ [32]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-27145.json 
│                       │     │                  ╰ [33]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-07-17T13:18:10.947Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-39822 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:893d450f302f8ce1e3a01b3b4799e113c5d87b501841082baa2baa
│                       │     │                   5c6567a8ac 
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
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:9d55762732135e94d7b2b586a9f648f9368e819c633d44cd423592
│                       │     │                   e2da97aad5 
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
│                       │     ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-42505 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5856 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                       │     │                  │         7b5687b2443e5cccf74 
│                       │     │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                       │     │                            9931ea661da63126f54 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:a698acec407ff38396f3fe69ca6b646fe6ad09feec6d1b3c27e3da
│                       │     │                   3cd8a5bd5d 
│                       │     ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
│                       │     │                   Encrypted Client Hello 
│                       │     ├ Description     : Handshakes which used Encrypted Client Hello could be
│                       │     │                   de-anonymized by a passive network observer due to a
│                       │     │                   disclosure of pre-shared key identities in the unencrypted
│                       │     │                   client hello. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-201 
│                       │     ├ VendorSeverity   ╭ bitnami: 2 
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
│                       ╰ [7] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : f77aad5d3fa73e61 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2af
│                             │                  │         7b5687b2443e5cccf74 
│                             │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01a
│                             │                            9931ea661da63126f54 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:fa73537e9eceb034a4f794602f8ab69d9e6a520b939640051a1302
│                             │                   639d9ae14d 
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
│                             ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
╰ [8] ╭ Target         : usr/share/grafana/data/plugins-bundled/zipkin/gpx_grafana-zipkin-datasource_linux_amd64 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ├ Packages        
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-29181 
                        │      ├ VendorIDs        ─ [0]: GHSA-mh2q-q3fh-2475 
                        │      ├ PkgID           : go.opentelemetry.io/otel@v1.40.0 
                        │      ├ PkgName         : go.opentelemetry.io/otel 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel@v1.40.0 
                        │      │                  ╰ UID : d19258ccd6affcd1 
                        │      ├ InstalledVersion: v1.40.0 
                        │      ├ FixedVersion    : 1.41.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-29181 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:cc690a8ef2bd9304040cf210792602abfbb34cfdb3ff54a109807
                        │      │                   f918fc91fac 
                        │      ├ Title           : github.com/open-telemetry/opentelemetry-go:
                        │      │                   OpenTelemetry-Go: Denial of Service via crafted multi-value
                        │      │                   baggage headers 
                        │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
                        │      │                   From 1.36.0 to 1.40.0, multi-value baggage: header
                        │      │                   extraction parses each header field-value independently and
                        │      │                   aggregates members across values. This allows an attacker to
                        │      │                    amplify cpu and allocations by sending many baggage: header
                        │      │                    lines, even when each individual value is within the
                        │      │                   8192-byte per-value parse limit. This vulnerability is fixed
                        │      │                    in 1.41.0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ azure : 2 
                        │      │                  ├ ghsa  : 3 
                        │      │                  ├ photon: 3 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                  │        │           /A:H 
                        │      │                  │        ╰ V3Score : 7.5 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:25271 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-29181 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/show_bug.cgi?id=2456252 
                        │      │                  ├ [3] : https://github.com/open-telemetry/opentelemetry-go 
                        │      │                  ├ [4] : https://github.com/open-telemetry/opentelemetry-go/co
                        │      │                  │       mmit/aa1894e09e3fe66860c7885cb40f98901b35277f 
                        │      │                  ├ [5] : https://github.com/open-telemetry/opentelemetry-go/pu
                        │      │                  │       ll/7880 
                        │      │                  ├ [6] : https://github.com/open-telemetry/opentelemetry-go/re
                        │      │                  │       leases/tag/v1.41.0 
                        │      │                  ├ [7] : https://github.com/open-telemetry/opentelemetry-go/se
                        │      │                  │       curity/advisories/GHSA-mh2q-q3fh-2475 
                        │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2026-29181 
                        │      │                  ├ [9] : https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-29181.json 
                        │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2026-29181 
                        │      ├ PublishedDate   : 2026-04-07T21:17:16.003Z 
                        │      ╰ LastModifiedDate: 2026-07-15T02:19:24.677Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2026-39883 
                        │      ├ VendorIDs        ─ [0]: GHSA-hfvc-g4fc-pqhx 
                        │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.40.0 
                        │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.40.0 
                        │      │                  ╰ UID : a801227131958a6e 
                        │      ├ InstalledVersion: v1.40.0 
                        │      ├ FixedVersion    : 1.43.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:51f9c18f8f64f5d1bd620c329875fadcf1bee356546faa198bfcd
                        │      │                   17e4ab09ced 
                        │      ├ Title           : github.com/open-telemetry/opentelemetry-go:
                        │      │                   OpenTelemetry-Go: Arbitrary code execution via PATH
                        │      │                   hijacking on BSD/Solaris 
                        │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
                        │      │                   From 1.15.0 to 1.42.0, the fix for CVE-2026-24051 changed
                        │      │                   the Darwin ioreg command to use an absolute path but left
                        │      │                   the BSD kenv command using a bare name, allowing the same
                        │      │                   PATH hijacking attack on BSD and Solaris platforms. This
                        │      │                   vulnerability is fixed in 1.43.0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-426 
                        │      ├ VendorSeverity   ╭ ghsa  : 3 
                        │      │                  ├ nvd   : 3 
                        │      │                  ├ photon: 3 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/
                        │      │                  │        │            VI:H/VA:H/SC:N/SI:N/SA:N 
                        │      │                  │        ╰ V40Score : 7.3 
                        │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H
                        │      │                  │        │           /A:H 
                        │      │                  │        ╰ V3Score : 7 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 8.8 
                        │      ├ References       ╭ [0] : http://github.com/open-telemetry/opentelemetry-go/rel
                        │      │                  │       eases/tag/v1.43.0 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:26254 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:26257 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:37387 
                        │      │                  ├ [4] : https://access.redhat.com/security/cve/CVE-2026-39883 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2456718 
                        │      │                  ├ [6] : https://github.com/open-telemetry/opentelemetry-go 
                        │      │                  ├ [7] : https://github.com/open-telemetry/opentelemetry-go/se
                        │      │                  │       curity/advisories/GHSA-hfvc-g4fc-pqhx 
                        │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2026-39883 
                        │      │                  ├ [9] : https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39883.json 
                        │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2026-39883 
                        │      ├ PublishedDate   : 2026-04-08T21:17:00.697Z 
                        │      ╰ LastModifiedDate: 2026-07-15T02:20:53.623Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-25681 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5029 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:b4117afc7d5cb7c3c34e46df93069624da51abf45265ec19a8ffb
                        │      │                   2058e36551a 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:25:03.343Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-27136 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5030 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4c2a591258431346a9aed0b4d650d9a537390cf41673eff807e0c
                        │      │                   d59e9ed3fc9 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:26:43.803Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.53.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:79411950ea27dee3e66cdf2b30ce167f479f2b5b2d53cb349ff32
                        │      │                   8a3cf0d026c 
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
                        │      │                  ├ [8] : https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [10]: https://github.com/golang/go/issues/78476 
                        │      │                  ├ [11]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [12]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [13]: https://go.dev/cl/761581 
                        │      │                  ├ [14]: https://go.dev/cl/761640 
                        │      │                  ├ [15]: https://go.dev/issue/78476 
                        │      │                  ├ [16]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [17]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [18]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [19]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [20]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [21]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [22]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [23]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [24]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [25]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [26]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-07-15T02:20:18.21Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5050461c70e8fa82a4f684502c1a6fbf3f6bbe36f48fe9103d176
                        │      │                   56391653a21 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:26546 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:26547 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:30650 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:30651 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:30853 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:30854 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:30855 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:33155 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:33160 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:33163 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:33173 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:33183 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:33524 
                        │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:33531 
                        │      │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:34342 
                        │      │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:34789 
                        │      │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:35826 
                        │      │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:35827 
                        │      │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:35828 
                        │      │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:35829 
                        │      │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:35830 
                        │      │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:35831 
                        │      │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:35993 
                        │      │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:35994 
                        │      │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:36105 
                        │      │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:36167 
                        │      │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:36207 
                        │      │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:36651 
                        │      │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:36796 
                        │      │                  ├ [35]: https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [36]: https://access.redhat.com/errata/RHSA-2026:36808 
                        │      │                  ├ [37]: https://access.redhat.com/errata/RHSA-2026:36820 
                        │      │                  ├ [38]: https://access.redhat.com/errata/RHSA-2026:36883 
                        │      │                  ├ [39]: https://access.redhat.com/errata/RHSA-2026:37387 
                        │      │                  ├ [40]: https://access.redhat.com/errata/RHSA-2026:37435 
                        │      │                  ├ [41]: https://access.redhat.com/errata/RHSA-2026:37436 
                        │      │                  ├ [42]: https://access.redhat.com/errata/RHSA-2026:38995 
                        │      │                  ├ [43]: https://access.redhat.com/errata/RHSA-2026:39005 
                        │      │                  ├ [44]: https://access.redhat.com/errata/RHSA-2026:39573 
                        │      │                  ├ [45]: https://access.redhat.com/errata/RHSA-2026:39879 
                        │      │                  ├ [46]: https://access.redhat.com/errata/RHSA-2026:40118 
                        │      │                  ├ [47]: https://access.redhat.com/errata/RHSA-2026:40119 
                        │      │                  ├ [48]: https://access.redhat.com/errata/RHSA-2026:40262 
                        │      │                  ├ [49]: https://access.redhat.com/errata/RHSA-2026:40945 
                        │      │                  ├ [50]: https://access.redhat.com/errata/RHSA-2026:41019 
                        │      │                  ├ [51]: https://access.redhat.com/errata/RHSA-2026:41030 
                        │      │                  ├ [52]: https://access.redhat.com/errata/RHSA-2026:41031 
                        │      │                  ├ [53]: https://access.redhat.com/errata/RHSA-2026:41036 
                        │      │                  ├ [54]: https://access.redhat.com/errata/RHSA-2026:41055 
                        │      │                  ├ [55]: https://access.redhat.com/errata/RHSA-2026:41066 
                        │      │                  ├ [56]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [57]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [58]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [59]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [60]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39821 
                        │      │                  ├ [61]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39822 
                        │      │                  ├ [62]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [63]: https://errata.rockylinux.org/RLSA-2026:37435 
                        │      │                  ├ [64]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [65]: https://go.dev/cl/767220 
                        │      │                  ├ [66]: https://go.dev/issue/78760 
                        │      │                  ├ [67]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [68]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [69]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
                        │      │                  ├ [70]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [71]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [72]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39821.json 
                        │      │                  ├ [73]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [74]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:31.383Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:fe1a78b5edb7cce125f6383e4cb75ed3563e289130526676a80c3
                        │      │                   c8bf4987e81 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:25:03.14Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-42502 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5027 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7473db7026804d9b35ce32e14a8fe01d706bd3d1a63ab3cfa7d86
                        │      │                   e5cc3fec175 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.593Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-42506 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5025 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:09bb40188a2eb2c3aa8d48fb59999f7e40b00422fb4c2e7e6dfb5
                        │      │                   725fe978b27 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.993Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.56.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5452a82784c4564ea353f43ce4f7c68294c71e27774f1d78eca23
                        │      │                   3a4fd5f7971 
                        │      ├ Title           : Parsing an invalid SVCB or HTTPS RR can panic in
                        │      │                   golang.org/x/net/dns/dnsmessage 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : UNKNOWN 
                        │      ╰ References       ╭ [0]: https://go.dev/cl/786345 
                        │                         ├ [1]: https://go.dev/issue/79795 
                        │                         ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5942 
                        ├ [10] ╭ VulnerabilityID : CVE-2026-39824 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5024 
                        │      ├ PkgID           : golang.org/x/sys@v0.40.0 
                        │      ├ PkgName         : golang.org/x/sys 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/sys@v0.40.0 
                        │      │                  ╰ UID : 9084712f03f133bd 
                        │      ├ InstalledVersion: v0.40.0 
                        │      ├ FixedVersion    : 0.44.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:18d8d0ab7638695f10e3574ad1ee33c2b17ae4a002112826704e4
                        │      │                   387dba1970e 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.62Z 
                        ├ [11] ╭ VulnerabilityID : CVE-2026-56852 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5970 
                        │      ├ PkgID           : golang.org/x/text@v0.33.0 
                        │      ├ PkgName         : golang.org/x/text 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/text@v0.33.0 
                        │      │                  ╰ UID : 1d58fdff500f9aea 
                        │      ├ InstalledVersion: v0.33.0 
                        │      ├ FixedVersion    : 0.39.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7dba2f7559c3e6ab7f5c6d6d99f06cacc1f870b0ccdf904b2b46a
                        │      │                   3d81a184c66 
                        │      ├ Title           : Infinite loop on invalid input in golang.org/x/text 
                        │      ├ Description     : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing invalid UTF-8 bytes. 
                        │      ├ Severity        : UNKNOWN 
                        │      ╰ References       ╭ [0]: https://go.dev/cl/794100 
                        │                         ├ [1]: https://go.dev/issue/80142 
                        │                         ╰ [2]: https://pkg.go.dev/vuln/GO-2026-5970 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-25679 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4601 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.8, 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25679 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:60c62f0605360d6e38653935164ade468d57d5db5adf626e36eb0
                        │      │                   3b66b9e04c3 
                        │      ├ Title           : net/url: Incorrect parsing of IPv6 host literals in net/url 
                        │      ├ Description     : url.Parse insufficiently validated the host/authority
                        │      │                   component and accepted some invalid URLs. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-425 
                        │      │                  ╰ [1]: CWE-1286 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ azure      : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:10065 
                        │      │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:10125 
                        │      │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:10133 
                        │      │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:10140 
                        │      │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:10141 
                        │      │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:10158 
                        │      │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:10169 
                        │      │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:10175 
                        │      │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:10184 
                        │      │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:10225 
                        │      │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:10250 
                        │      │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:10701 
                        │      │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:10712 
                        │      │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:10929 
                        │      │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:11217 
                        │      │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:11375 
                        │      │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:11412 
                        │      │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:11413 
                        │      │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:11686 
                        │      │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:11688 
                        │      │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:11747 
                        │      │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:11749 
                        │      │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:11768 
                        │      │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:11800 
                        │      │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:11856 
                        │      │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:11916 
                        │      │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:11996 
                        │      │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:12028 
                        │      │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:12029 
                        │      │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:12030 
                        │      │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:12031 
                        │      │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:12032 
                        │      │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:12033 
                        │      │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:12282 
                        │      │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:13508 
                        │      │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:13512 
                        │      │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:13545 
                        │      │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:13642 
                        │      │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:13643 
                        │      │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:13671 
                        │      │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:13791 
                        │      │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:13829 
                        │      │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:14020 
                        │      │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:14100 
                        │      │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:14774 
                        │      │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:14868 
                        │      │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:14879 
                        │      │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:15091 
                        │      │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:16102 
                        │      │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:16696 
                        │      │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:16874 
                        │      │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:16875 
                        │      │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:17040 
                        │      │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:17084 
                        │      │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:17287 
                        │      │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:17598 
                        │      │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:19017 
                        │      │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:19022 
                        │      │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:19026 
                        │      │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:19027 
                        │      │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:19031 
                        │      │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:19032 
                        │      │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:19049 
                        │      │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:19055 
                        │      │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:19126 
                        │      │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:19128 
                        │      │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:19132 
                        │      │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:19133 
                        │      │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:19135 
                        │      │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:19181 
                        │      │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:19184 
                        │      │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:19185 
                        │      │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:19207 
                        │      │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:19350 
                        │      │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:19353 
                        │      │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:19375 
                        │      │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:19475 
                        │      │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:19634 
                        │      │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:19719 
                        │      │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:19720 
                        │      │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:19721 
                        │      │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:19750 
                        │      │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:20041 
                        │      │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:20088 
                        │      │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:20581 
                        │      │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:20582 
                        │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:20584 
                        │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:20889 
                        │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:21017 
                        │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:21655 
                        │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:21657 
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:21691 
                        │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:21696 
                        │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:21769 
                        │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:22347 
                        │      │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:22423 
                        │      │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:22450 
                        │      │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:22627 
                        │      │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:22714 
                        │      │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:22733 
                        │      │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:22862 
                        │      │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:22937 
                        │      │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:23228 
                        │      │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:23345 
                        │      │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:24386 
                        │      │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:24853 
                        │      │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:25043 
                        │      │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:25127 
                        │      │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:25180 
                        │      │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:25248 
                        │      │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:25250 
                        │      │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:25251 
                        │      │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:25252 
                        │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:25253 
                        │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:26445 
                        │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:26527 
                        │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:26541 
                        │      │                  ├ [117]: https://access.redhat.com/errata/RHSA-2026:26568 
                        │      │                  ├ [118]: https://access.redhat.com/errata/RHSA-2026:26585 
                        │      │                  ├ [119]: https://access.redhat.com/errata/RHSA-2026:26636 
                        │      │                  ├ [120]: https://access.redhat.com/errata/RHSA-2026:27076 
                        │      │                  ├ [121]: https://access.redhat.com/errata/RHSA-2026:28047 
                        │      │                  ├ [122]: https://access.redhat.com/errata/RHSA-2026:28441 
                        │      │                  ├ [123]: https://access.redhat.com/errata/RHSA-2026:28886 
                        │      │                  ├ [124]: https://access.redhat.com/errata/RHSA-2026:28893 
                        │      │                  ├ [125]: https://access.redhat.com/errata/RHSA-2026:28961 
                        │      │                  ├ [126]: https://access.redhat.com/errata/RHSA-2026:29035 
                        │      │                  ├ [127]: https://access.redhat.com/errata/RHSA-2026:29195 
                        │      │                  ├ [128]: https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [129]: https://access.redhat.com/errata/RHSA-2026:29702 
                        │      │                  ├ [130]: https://access.redhat.com/errata/RHSA-2026:29703 
                        │      │                  ├ [131]: https://access.redhat.com/errata/RHSA-2026:29854 
                        │      │                  ├ [132]: https://access.redhat.com/errata/RHSA-2026:33722 
                        │      │                  ├ [133]: https://access.redhat.com/errata/RHSA-2026:34097 
                        │      │                  ├ [134]: https://access.redhat.com/errata/RHSA-2026:34365 
                        │      │                  ├ [135]: https://access.redhat.com/errata/RHSA-2026:36317 
                        │      │                  ├ [136]: https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [137]: https://access.redhat.com/errata/RHSA-2026:36651 
                        │      │                  ├ [138]: https://access.redhat.com/errata/RHSA-2026:36796 
                        │      │                  ├ [139]: https://access.redhat.com/errata/RHSA-2026:39810 
                        │      │                  ├ [140]: https://access.redhat.com/errata/RHSA-2026:40118 
                        │      │                  ├ [141]: https://access.redhat.com/errata/RHSA-2026:40945 
                        │      │                  ├ [142]: https://access.redhat.com/errata/RHSA-2026:41019 
                        │      │                  ├ [143]: https://access.redhat.com/errata/RHSA-2026:5110 
                        │      │                  ├ [144]: https://access.redhat.com/errata/RHSA-2026:5549 
                        │      │                  ├ [145]: https://access.redhat.com/errata/RHSA-2026:5941 
                        │      │                  ├ [146]: https://access.redhat.com/errata/RHSA-2026:5942 
                        │      │                  ├ [147]: https://access.redhat.com/errata/RHSA-2026:5943 
                        │      │                  ├ [148]: https://access.redhat.com/errata/RHSA-2026:5944 
                        │      │                  ├ [149]: https://access.redhat.com/errata/RHSA-2026:6341 
                        │      │                  ├ [150]: https://access.redhat.com/errata/RHSA-2026:6344 
                        │      │                  ├ [151]: https://access.redhat.com/errata/RHSA-2026:6382 
                        │      │                  ├ [152]: https://access.redhat.com/errata/RHSA-2026:6383 
                        │      │                  ├ [153]: https://access.redhat.com/errata/RHSA-2026:6388 
                        │      │                  ├ [154]: https://access.redhat.com/errata/RHSA-2026:6564 
                        │      │                  ├ [155]: https://access.redhat.com/errata/RHSA-2026:6720 
                        │      │                  ├ [156]: https://access.redhat.com/errata/RHSA-2026:6802 
                        │      │                  ├ [157]: https://access.redhat.com/errata/RHSA-2026:6949 
                        │      │                  ├ [158]: https://access.redhat.com/errata/RHSA-2026:7005 
                        │      │                  ├ [159]: https://access.redhat.com/errata/RHSA-2026:7009 
                        │      │                  ├ [160]: https://access.redhat.com/errata/RHSA-2026:7011 
                        │      │                  ├ [161]: https://access.redhat.com/errata/RHSA-2026:7259 
                        │      │                  ├ [162]: https://access.redhat.com/errata/RHSA-2026:7291 
                        │      │                  ├ [163]: https://access.redhat.com/errata/RHSA-2026:7315 
                        │      │                  ├ [164]: https://access.redhat.com/errata/RHSA-2026:7328 
                        │      │                  ├ [165]: https://access.redhat.com/errata/RHSA-2026:7385 
                        │      │                  ├ [166]: https://access.redhat.com/errata/RHSA-2026:7665 
                        │      │                  ├ [167]: https://access.redhat.com/errata/RHSA-2026:7669 
                        │      │                  ├ [168]: https://access.redhat.com/errata/RHSA-2026:7674 
                        │      │                  ├ [169]: https://access.redhat.com/errata/RHSA-2026:7833 
                        │      │                  ├ [170]: https://access.redhat.com/errata/RHSA-2026:7834 
                        │      │                  ├ [171]: https://access.redhat.com/errata/RHSA-2026:7876 
                        │      │                  ├ [172]: https://access.redhat.com/errata/RHSA-2026:7877 
                        │      │                  ├ [173]: https://access.redhat.com/errata/RHSA-2026:7878 
                        │      │                  ├ [174]: https://access.redhat.com/errata/RHSA-2026:7879 
                        │      │                  ├ [175]: https://access.redhat.com/errata/RHSA-2026:7883 
                        │      │                  ├ [176]: https://access.redhat.com/errata/RHSA-2026:7992 
                        │      │                  ├ [177]: https://access.redhat.com/errata/RHSA-2026:8151 
                        │      │                  ├ [178]: https://access.redhat.com/errata/RHSA-2026:8167 
                        │      │                  ├ [179]: https://access.redhat.com/errata/RHSA-2026:8314 
                        │      │                  ├ [180]: https://access.redhat.com/errata/RHSA-2026:8322 
                        │      │                  ├ [181]: https://access.redhat.com/errata/RHSA-2026:8324 
                        │      │                  ├ [182]: https://access.redhat.com/errata/RHSA-2026:8337 
                        │      │                  ├ [183]: https://access.redhat.com/errata/RHSA-2026:8338 
                        │      │                  ├ [184]: https://access.redhat.com/errata/RHSA-2026:8433 
                        │      │                  ├ [185]: https://access.redhat.com/errata/RHSA-2026:8434 
                        │      │                  ├ [186]: https://access.redhat.com/errata/RHSA-2026:8456 
                        │      │                  ├ [187]: https://access.redhat.com/errata/RHSA-2026:8483 
                        │      │                  ├ [188]: https://access.redhat.com/errata/RHSA-2026:8484 
                        │      │                  ├ [189]: https://access.redhat.com/errata/RHSA-2026:8490 
                        │      │                  ├ [190]: https://access.redhat.com/errata/RHSA-2026:8491 
                        │      │                  ├ [191]: https://access.redhat.com/errata/RHSA-2026:8493 
                        │      │                  ├ [192]: https://access.redhat.com/errata/RHSA-2026:8840 
                        │      │                  ├ [193]: https://access.redhat.com/errata/RHSA-2026:8841 
                        │      │                  ├ [194]: https://access.redhat.com/errata/RHSA-2026:8842 
                        │      │                  ├ [195]: https://access.redhat.com/errata/RHSA-2026:8845 
                        │      │                  ├ [196]: https://access.redhat.com/errata/RHSA-2026:8847 
                        │      │                  ├ [197]: https://access.redhat.com/errata/RHSA-2026:8848 
                        │      │                  ├ [198]: https://access.redhat.com/errata/RHSA-2026:8849 
                        │      │                  ├ [199]: https://access.redhat.com/errata/RHSA-2026:8851 
                        │      │                  ├ [200]: https://access.redhat.com/errata/RHSA-2026:8852 
                        │      │                  ├ [201]: https://access.redhat.com/errata/RHSA-2026:8853 
                        │      │                  ├ [202]: https://access.redhat.com/errata/RHSA-2026:8855 
                        │      │                  ├ [203]: https://access.redhat.com/errata/RHSA-2026:8856 
                        │      │                  ├ [204]: https://access.redhat.com/errata/RHSA-2026:8860 
                        │      │                  ├ [205]: https://access.redhat.com/errata/RHSA-2026:8877 
                        │      │                  ├ [206]: https://access.redhat.com/errata/RHSA-2026:8878 
                        │      │                  ├ [207]: https://access.redhat.com/errata/RHSA-2026:8879 
                        │      │                  ├ [208]: https://access.redhat.com/errata/RHSA-2026:8881 
                        │      │                  ├ [209]: https://access.redhat.com/errata/RHSA-2026:8882 
                        │      │                  ├ [210]: https://access.redhat.com/errata/RHSA-2026:8930 
                        │      │                  ├ [211]: https://access.redhat.com/errata/RHSA-2026:8931 
                        │      │                  ├ [212]: https://access.redhat.com/errata/RHSA-2026:8949 
                        │      │                  ├ [213]: https://access.redhat.com/errata/RHSA-2026:9043 
                        │      │                  ├ [214]: https://access.redhat.com/errata/RHSA-2026:9044 
                        │      │                  ├ [215]: https://access.redhat.com/errata/RHSA-2026:9052 
                        │      │                  ├ [216]: https://access.redhat.com/errata/RHSA-2026:9090 
                        │      │                  ├ [217]: https://access.redhat.com/errata/RHSA-2026:9093 
                        │      │                  ├ [218]: https://access.redhat.com/errata/RHSA-2026:9094 
                        │      │                  ├ [219]: https://access.redhat.com/errata/RHSA-2026:9097 
                        │      │                  ├ [220]: https://access.redhat.com/errata/RHSA-2026:9098 
                        │      │                  ├ [221]: https://access.redhat.com/errata/RHSA-2026:9108 
                        │      │                  ├ [222]: https://access.redhat.com/errata/RHSA-2026:9109 
                        │      │                  ├ [223]: https://access.redhat.com/errata/RHSA-2026:9385 
                        │      │                  ├ [224]: https://access.redhat.com/errata/RHSA-2026:9434 
                        │      │                  ├ [225]: https://access.redhat.com/errata/RHSA-2026:9435 
                        │      │                  ├ [226]: https://access.redhat.com/errata/RHSA-2026:9436 
                        │      │                  ├ [227]: https://access.redhat.com/errata/RHSA-2026:9439 
                        │      │                  ├ [228]: https://access.redhat.com/errata/RHSA-2026:9440 
                        │      │                  ├ [229]: https://access.redhat.com/errata/RHSA-2026:9448 
                        │      │                  ├ [230]: https://access.redhat.com/errata/RHSA-2026:9453 
                        │      │                  ├ [231]: https://access.redhat.com/errata/RHSA-2026:9461 
                        │      │                  ├ [232]: https://access.redhat.com/errata/RHSA-2026:9695 
                        │      │                  ├ [233]: https://access.redhat.com/errata/RHSA-2026:9742 
                        │      │                  ├ [234]: https://access.redhat.com/errata/RHSA-2026:9872 
                        │      │                  ├ [235]: https://access.redhat.com/security/cve/CVE-2026-25679 
                        │      │                  ├ [236]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [237]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [238]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [239]: https://errata.almalinux.org/9/ALSA-2026-9044.html 
                        │      │                  ├ [240]: https://errata.rockylinux.org/RLSA-2026:9044 
                        │      │                  ├ [241]: https://go.dev/cl/752180 
                        │      │                  ├ [242]: https://go.dev/issue/77578 
                        │      │                  ├ [243]: https://groups.google.com/g/golang-announce/c/EdhZqr
                        │      │                  │        Q98hk 
                        │      │                  ├ [244]: https://linux.oracle.com/cve/CVE-2026-25679.html 
                        │      │                  ├ [245]: https://linux.oracle.com/errata/ELSA-2026-9044.html 
                        │      │                  ├ [246]: https://nvd.nist.gov/vuln/detail/CVE-2026-25679 
                        │      │                  ├ [247]: https://pkg.go.dev/vuln/GO-2026-4601 
                        │      │                  ├ [248]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-25679.json 
                        │      │                  ╰ [249]: https://www.cve.org/CVERecord?id=CVE-2026-25679 
                        │      ├ PublishedDate   : 2026-03-06T22:16:00.72Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:00.073Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:628fcfe74a626a6427ea8f937f6088f30eb49c57dcd179710a039
                        │      │                   094777ced7d 
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
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29981 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:35832 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36317 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:38995 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:39005 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39573 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39879 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:41030 
                        │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41036 
                        │      │                  ├ [16]: https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [17]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [18]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [19]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [20]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [23]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
                        │      │                  ├ [24]: https://errata.rockylinux.org/RLSA-2026:36317 
                        │      │                  ├ [25]: https://go.dev/cl/783621 
                        │      │                  ├ [26]: https://go.dev/issue/79694 
                        │      │                  ├ [27]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [28]: https://linux.oracle.com/cve/CVE-2026-27145.html 
                        │      │                  ├ [29]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
                        │      │                  ├ [30]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [31]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [32]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [33]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:10.947Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-32280 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4947 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32280 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:73ed73957e49dcefa568a5901acfbdc39b21195d2f7d5460e67ae
                        │      │                   3fd81b57bc1 
                        │      ├ Title           : crypto/x509: crypto/tls: golang: Go: Denial of Service
                        │      │                   vulnerability in certificate chain building 
                        │      ├ Description     : During chain building, the amount of work that is done is
                        │      │                   not correctly limited when a large number of intermediate
                        │      │                   certificates are passed in VerifyOptions.Intermediates,
                        │      │                   which can lead to a denial of service. This affects both
                        │      │                   direct users of crypto/x509 and users of crypto/tls. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ├ rocky      : 3 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:10217 
                        │      │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:10219 
                        │      │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:10704 
                        │      │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:11507 
                        │      │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:11514 
                        │      │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:11688 
                        │      │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:13545 
                        │      │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:13791 
                        │      │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:13826 
                        │      │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:13829 
                        │      │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:14020 
                        │      │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:14162 
                        │      │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:14200 
                        │      │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:14391 
                        │      │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:15980 
                        │      │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:16021 
                        │      │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:16024 
                        │      │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:16101 
                        │      │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:16476 
                        │      │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:16477 
                        │      │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:16505 
                        │      │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:16508 
                        │      │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:16532 
                        │      │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:16534 
                        │      │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:16535 
                        │      │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:16537 
                        │      │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:16542 
                        │      │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:16874 
                        │      │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:16875 
                        │      │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:17084 
                        │      │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:17287 
                        │      │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:18027 
                        │      │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:18032 
                        │      │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:19133 
                        │      │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:19135 
                        │      │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:19144 
                        │      │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:19350 
                        │      │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:19353 
                        │      │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:19375 
                        │      │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:19450 
                        │      │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:19550 
                        │      │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:19634 
                        │      │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:19714 
                        │      │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:19715 
                        │      │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:19719 
                        │      │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:19720 
                        │      │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:19721 
                        │      │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:19722 
                        │      │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:19750 
                        │      │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:19839 
                        │      │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:20556 
                        │      │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:20569 
                        │      │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:20570 
                        │      │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:20571 
                        │      │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:20607 
                        │      │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:20608 
                        │      │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:20609 
                        │      │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:20889 
                        │      │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:21017 
                        │      │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:21338 
                        │      │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:21655 
                        │      │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:21769 
                        │      │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:21772 
                        │      │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:22130 
                        │      │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:22141 
                        │      │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:22258 
                        │      │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:22260 
                        │      │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:22268 
                        │      │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:22309 
                        │      │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:22347 
                        │      │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:22415 
                        │      │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:22422 
                        │      │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:22465 
                        │      │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:22485 
                        │      │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:22709 
                        │      │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:22713 
                        │      │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:22840 
                        │      │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:22862 
                        │      │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:22958 
                        │      │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:22959 
                        │      │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:22960 
                        │      │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:22961 
                        │      │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:22962 
                        │      │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:23102 
                        │      │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:23103 
                        │      │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:23244 
                        │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:23345 
                        │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:23361 
                        │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:24337 
                        │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:24359 
                        │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:24470 
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:24478 
                        │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:24716 
                        │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:24761 
                        │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:24762 
                        │      │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:24853 
                        │      │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:24977 
                        │      │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:25089 
                        │      │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:25127 
                        │      │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:25180 
                        │      │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:26447 
                        │      │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:26568 
                        │      │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:26571 
                        │      │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:26585 
                        │      │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:26636 
                        │      │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:27076 
                        │      │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:28038 
                        │      │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:28047 
                        │      │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:28074 
                        │      │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:28196 
                        │      │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:28198 
                        │      │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:28441 
                        │      │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:28886 
                        │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:28961 
                        │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:29035 
                        │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:29195 
                        │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [117]: https://access.redhat.com/errata/RHSA-2026:29702 
                        │      │                  ├ [118]: https://access.redhat.com/errata/RHSA-2026:29703 
                        │      │                  ├ [119]: https://access.redhat.com/errata/RHSA-2026:29854 
                        │      │                  ├ [120]: https://access.redhat.com/errata/RHSA-2026:33722 
                        │      │                  ├ [121]: https://access.redhat.com/errata/RHSA-2026:34097 
                        │      │                  ├ [122]: https://access.redhat.com/errata/RHSA-2026:34192 
                        │      │                  ├ [123]: https://access.redhat.com/errata/RHSA-2026:34196 
                        │      │                  ├ [124]: https://access.redhat.com/errata/RHSA-2026:34197 
                        │      │                  ├ [125]: https://access.redhat.com/errata/RHSA-2026:34365 
                        │      │                  ├ [126]: https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [127]: https://access.redhat.com/errata/RHSA-2026:36651 
                        │      │                  ├ [128]: https://access.redhat.com/errata/RHSA-2026:36796 
                        │      │                  ├ [129]: https://access.redhat.com/errata/RHSA-2026:39810 
                        │      │                  ├ [130]: https://access.redhat.com/errata/RHSA-2026:39894 
                        │      │                  ├ [131]: https://access.redhat.com/errata/RHSA-2026:40118 
                        │      │                  ├ [132]: https://access.redhat.com/errata/RHSA-2026:40945 
                        │      │                  ├ [133]: https://access.redhat.com/errata/RHSA-2026:41019 
                        │      │                  ├ [134]: https://access.redhat.com/errata/RHSA-2026:9385 
                        │      │                  ├ [135]: https://access.redhat.com/security/cve/CVE-2026-32280 
                        │      │                  ├ [136]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [137]: https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [138]: https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [139]: https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [140]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [141]: https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [142]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [143]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [144]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [145]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32280 
                        │      │                  ├ [146]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32281 
                        │      │                  ├ [147]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32283 
                        │      │                  ├ [148]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [149]: https://errata.rockylinux.org/RLSA-2026:29703 
                        │      │                  ├ [150]: https://go.dev/cl/758320 
                        │      │                  ├ [151]: https://go.dev/issue/78282 
                        │      │                  ├ [152]: https://groups.google.com/g/golang-announce/c/0uYbvb
                        │      │                  │        PZRWU 
                        │      │                  ├ [153]: https://linux.oracle.com/cve/CVE-2026-32280.html 
                        │      │                  ├ [154]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [155]: https://nvd.nist.gov/vuln/detail/CVE-2026-32280 
                        │      │                  ├ [156]: https://pkg.go.dev/vuln/GO-2026-4947 
                        │      │                  ├ [157]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-32280.json 
                        │      │                  ╰ [158]: https://www.cve.org/CVERecord?id=CVE-2026-32280 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.247Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:13.893Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2026-32281 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4946 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32281 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:52f1df1e4db7a6d8c247508bc4add8015a5f54d79ae0f2029ef6e
                        │      │                   244a6dcac2e 
                        │      ├ Title           : crypto/x509: golang: Go crypto/x509: Denial of Service via
                        │      │                   inefficient certificate chain validation 
                        │      ├ Description     : Validating certificate chains which use policies is
                        │      │                   unexpectedly inefficient when certificates in the chain
                        │      │                   contain a very large number of policy mappings, possibly
                        │      │                   causing denial of service. This only affects validation of
                        │      │                   otherwise trusted certificate chains, issued by a root CA in
                        │      │                    the VerifyOptions.Roots CertPool, or in the system
                        │      │                   certificate pool. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 5.9 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29703 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-32281 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [10]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [11]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [12]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32281 
                        │      │                  ├ [13]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [14]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [15]: https://errata.rockylinux.org/RLSA-2026:29703 
                        │      │                  ├ [16]: https://go.dev/cl/758061 
                        │      │                  ├ [17]: https://go.dev/issue/78281 
                        │      │                  ├ [18]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [19]: https://linux.oracle.com/cve/CVE-2026-32281.html 
                        │      │                  ├ [20]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [21]: https://nvd.nist.gov/vuln/detail/CVE-2026-32281 
                        │      │                  ├ [22]: https://pkg.go.dev/vuln/GO-2026-4946 
                        │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2026-32281 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.35Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:35:28.98Z 
                        ├ [16] ╭ VulnerabilityID : CVE-2026-32283 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4870 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32283 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:b6e85991376c30807922dd93790436a3741f620cbe5e5289a9352
                        │      │                   0cdb45fe8d7 
                        │      ├ Title           : crypto/tls: golang: Go crypto/tls: Denial of Service via
                        │      │                   multiple TLS 1.3 key update messages 
                        │      ├ Description     : If one side of the TLS connection sends multiple key update
                        │      │                   messages post-handshake in a single record, the connection
                        │      │                   can deadlock, causing uncontrolled consumption of resources.
                        │      │                    This can lead to a denial of service. This only affects TLS
                        │      │                    1.3. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-770 
                        │      │                  ╰ [1]: CWE-764 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:10217 
                        │      │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:10219 
                        │      │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:10704 
                        │      │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:11507 
                        │      │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:11514 
                        │      │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:11704 
                        │      │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:11711 
                        │      │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:11712 
                        │      │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:11863 
                        │      │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:11881 
                        │      │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:14162 
                        │      │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:14200 
                        │      │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:14391 
                        │      │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:15980 
                        │      │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:16021 
                        │      │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:16024 
                        │      │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:16101 
                        │      │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:16102 
                        │      │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:16875 
                        │      │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:17075 
                        │      │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:17084 
                        │      │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:17287 
                        │      │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:18027 
                        │      │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:18032 
                        │      │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:19126 
                        │      │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:19132 
                        │      │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:19133 
                        │      │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:19134 
                        │      │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:19135 
                        │      │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:19136 
                        │      │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:19137 
                        │      │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:19139 
                        │      │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:19144 
                        │      │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:19156 
                        │      │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:19350 
                        │      │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:19351 
                        │      │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:19352 
                        │      │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:19353 
                        │      │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:19369 
                        │      │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:19450 
                        │      │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:19550 
                        │      │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:19634 
                        │      │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:19714 
                        │      │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:19715 
                        │      │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:19719 
                        │      │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:19720 
                        │      │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:19721 
                        │      │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:19722 
                        │      │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:19750 
                        │      │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:19839 
                        │      │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:20556 
                        │      │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:20569 
                        │      │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:20570 
                        │      │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:20571 
                        │      │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:20607 
                        │      │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:20608 
                        │      │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:20609 
                        │      │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:21769 
                        │      │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:22347 
                        │      │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:22423 
                        │      │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:22450 
                        │      │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:22485 
                        │      │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:22709 
                        │      │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:22713 
                        │      │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:22714 
                        │      │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:22937 
                        │      │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:23102 
                        │      │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:23103 
                        │      │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:23228 
                        │      │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:23345 
                        │      │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:24337 
                        │      │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:24470 
                        │      │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:24761 
                        │      │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:24762 
                        │      │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:26447 
                        │      │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:26571 
                        │      │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:26636 
                        │      │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:27076 
                        │      │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:28038 
                        │      │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:28047 
                        │      │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:28074 
                        │      │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:29035 
                        │      │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:29195 
                        │      │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:29703 
                        │      │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:33722 
                        │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:34192 
                        │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:34196 
                        │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:34197 
                        │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:34365 
                        │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:36796 
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:39810 
                        │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:41019 
                        │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:7291 
                        │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:7385 
                        │      │                  ├ [95] : https://access.redhat.com/security/cve/CVE-2026-32283 
                        │      │                  ├ [96] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [97] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [98] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [99] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [100]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [101]: https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [102]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [103]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [104]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [105]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32280 
                        │      │                  ├ [106]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32281 
                        │      │                  ├ [107]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32283 
                        │      │                  ├ [108]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [109]: https://errata.rockylinux.org/RLSA-2026:29703 
                        │      │                  ├ [110]: https://go.dev/cl/763767 
                        │      │                  ├ [111]: https://go.dev/issue/78334 
                        │      │                  ├ [112]: https://groups.google.com/g/golang-announce/c/0uYbvb
                        │      │                  │        PZRWU 
                        │      │                  ├ [113]: https://linux.oracle.com/cve/CVE-2026-32283.html 
                        │      │                  ├ [114]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [115]: https://nvd.nist.gov/vuln/detail/CVE-2026-32283 
                        │      │                  ├ [116]: https://pkg.go.dev/vuln/GO-2026-4870 
                        │      │                  ├ [117]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-32283.json 
                        │      │                  ╰ [118]: https://www.cve.org/CVERecord?id=CVE-2026-32283 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.58Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:15.747Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2026-33811 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4981 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:79525ab70f1e59a93bda2991871e17398c08eae4e660d791c03c4
                        │      │                   cd4cc4a582f 
                        │      ├ Title           : net: golang: Go net package: Denial of Service via long
                        │      │                   CNAME response in LookupCNAME 
                        │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME response can trigger a double-free of C memory
                        │      │                   and a crash. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-415 
                        │      │                  ╰ [1]: CWE-1341 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
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
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:35832 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:35993 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:35994 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:35995 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:36207 
                        │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:36617 
                        │      │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:36625 
                        │      │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:36651 
                        │      │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:36776 
                        │      │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:36796 
                        │      │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:38504 
                        │      │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:39266 
                        │      │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:39272 
                        │      │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:39319 
                        │      │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:39573 
                        │      │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:39810 
                        │      │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:40118 
                        │      │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:40119 
                        │      │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:40945 
                        │      │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:41019 
                        │      │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:41030 
                        │      │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:41055 
                        │      │                  ├ [35]: https://access.redhat.com/security/cve/CVE-2026-33811 
                        │      │                  ├ [36]: https://bugzilla.redhat.com/2467822 
                        │      │                  ├ [37]: https://bugzilla.redhat.com/show_bug.cgi?id=2467822 
                        │      │                  ├ [38]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-33811 
                        │      │                  ├ [39]: https://errata.almalinux.org/9/ALSA-2026-39319.html 
                        │      │                  ├ [40]: https://errata.rockylinux.org/RLSA-2026:39319 
                        │      │                  ├ [41]: https://go.dev/cl/767860 
                        │      │                  ├ [42]: https://go.dev/issue/78803 
                        │      │                  ├ [43]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [44]: https://linux.oracle.com/cve/CVE-2026-33811.html 
                        │      │                  ├ [45]: https://linux.oracle.com/errata/ELSA-2026-39319.html 
                        │      │                  ├ [46]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ├ [47]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      │                  ├ [48]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33811.json 
                        │      │                  ╰ [49]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:24.597Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:1e177da58ea061306406757eb87df1c46423762bd766376ff4f18
                        │      │                   ff65f894e1b 
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
                        │      │                  ├ [8] : https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [10]: https://github.com/golang/go/issues/78476 
                        │      │                  ├ [11]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [12]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [13]: https://go.dev/cl/761581 
                        │      │                  ├ [14]: https://go.dev/cl/761640 
                        │      │                  ├ [15]: https://go.dev/issue/78476 
                        │      │                  ├ [16]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [17]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [18]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [19]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [20]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [21]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [22]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [23]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [24]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [25]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [26]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-07-15T02:20:18.21Z 
                        ├ [19] ╭ VulnerabilityID : CVE-2026-39820 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4986 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:dcc3e6775c855a9d3020767944b8331cbbfc0fb1b8e0b42c2b119
                        │      │                   3cf5d87d24f 
                        │      ├ Title           : net/mail: golang: Go net/mail: Denial of Service via crafted
                        │      │                    email inputs 
                        │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and ParseDate were able to trigger excessive CPU exhaustion
                        │      │                    and memory allocations. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-770 
                        │      │                  ╰ [1]: CWE-606 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:33120 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33123 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33142 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:33150 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36625 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:36754 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:40262 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:41031 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:41066 
                        │      │                  ├ [15]: https://access.redhat.com/security/cve/CVE-2026-39820 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2467820 
                        │      │                  ├ [17]: https://go.dev/cl/759940 
                        │      │                  ├ [18]: https://go.dev/issue/78566 
                        │      │                  ├ [19]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [20]: https://linux.oracle.com/cve/CVE-2026-39820.html 
                        │      │                  ├ [21]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [22]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ├ [23]: https://pkg.go.dev/vuln/GO-2026-4986 
                        │      │                  ├ [24]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39820.json 
                        │      │                  ╰ [25]: https://www.cve.org/CVERecord?id=CVE-2026-39820 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:30.537Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2026-39822 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4970 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:33e7f0c4d762290281f831e7ab8ebb724a5282e38baa6600a73e9
                        │      │                   11f0d5e0c96 
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
                        ├ [21] ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:778269e1611b13368bcad7dcc773507095f9816ce99b5934c754e
                        │      │                   18a6b9daf70 
                        │      ├ Title           : ELSA-2026-22121:  golang security update (IMPORTANT) 
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
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39836 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4971 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.593Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:40.34Z 
                        ├ [22] ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cfc64943b461bb64f08f74c442b94b321a9aa37c93a6979c0b753
                        │      │                   15d0a0a46ad 
                        │      ├ Title           : net/mail: golang: net/mail: Denial of Service via
                        │      │                   pathological email address parsing 
                        │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing an email address according to RFC 5322. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1046 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ╰ redhat     : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:17713 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:17714 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:33120 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33123 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33142 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:33150 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36625 
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:36754 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:40262 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:41031 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:41066 
                        │      │                  ├ [15]: https://access.redhat.com/security/cve/CVE-2026-42499 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2467809 
                        │      │                  ├ [17]: https://go.dev/cl/771520 
                        │      │                  ├ [18]: https://go.dev/issue/78987 
                        │      │                  ├ [19]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [20]: https://linux.oracle.com/cve/CVE-2026-42499.html 
                        │      │                  ├ [21]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [22]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ├ [23]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      │                  ├ [24]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-42499.json 
                        │      │                  ╰ [25]: https://www.cve.org/CVERecord?id=CVE-2026-42499 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-07-17T13:18:41.987Z 
                        ├ [23] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:121c0b1c12bb3f90ea59adef0afda16b58e27ffa892944187fb02
                        │      │                   4d94a7e6405 
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
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
                        ├ [24] ╭ VulnerabilityID : CVE-2026-27142 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4603 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.8, 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27142 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:15368827c06c6f9f083d4186abe30df13df366be02d714b7677e8
                        │      │                   f9498e538bb 
                        │      ├ Title           : html/template: URLs in meta content attribute actions are
                        │      │                   not escaped in html/template 
                        │      ├ Description     : Actions which insert URLs into the content attribute of HTML
                        │      │                    meta tags are not escaped. This can allow XSS if the meta
                        │      │                   tag also has an http-equiv attribute with the value
                        │      │                   "refresh". A new GODEBUG setting has been added,
                        │      │                   htmlmetacontenturlescape, which can be used to disable
                        │      │                   escaping URLs in actions in the meta content attribute which
                        │      │                    follow "url=" by setting htmlmetacontenturlescape=0. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ bitnami: 2 
                        │      │                  ├ photon : 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 5.4 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-27142 
                        │      │                  ├ [1]: https://go.dev/cl/752081 
                        │      │                  ├ [2]: https://go.dev/issue/77954 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/EdhZqrQ9
                        │      │                  │      8hk 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-27142 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4603 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-27142 
                        │      ├ PublishedDate   : 2026-03-06T22:16:01.177Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:26:44.67Z 
                        ├ [25] ╭ VulnerabilityID : CVE-2026-32282 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4864 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32282 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:bac8246e65a9dac745700459436207ae618728a1a8e366a783aa6
                        │      │                   908f143b610 
                        │      ├ Title           : golang: internal/syscall/unix: Root.Chmod can follow
                        │      │                   symlinks out of the root 
                        │      ├ Description     : On Linux, if the target of Root.Chmod is replaced with a
                        │      │                   symlink while the chmod operation is in progress, Chmod can
                        │      │                   operate on the target of the symlink, even when the target
                        │      │                   lies outside the root. The Linux fchmodat syscall silently
                        │      │                   ignores the AT_SYMLINK_NOFOLLOW flag, which Root.Chmod uses
                        │      │                   to avoid symlink traversal. Root.Chmod checks its target
                        │      │                   before acting and returns an error if the target is a
                        │      │                   symlink lying outside the root, so the impact is limited to
                        │      │                   cases where the target is replaced with a symlink between
                        │      │                   the check and operation. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-59 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ photon     : 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 6.4 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 6.4 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:
                        │      │                            │           H/A:H 
                        │      │                            ╰ V3Score : 7.8 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:19353 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-32282 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2449833 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2455470 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2456335 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2456336 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2434432 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2437111 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2445345 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2449833 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2455470 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2456336 
                        │      │                  ├ [17]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       25-61726 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       25-68121 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27137 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32282 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [24]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-33186 
                        │      │                  ├ [25]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-34986 
                        │      │                  ├ [26]: https://errata.almalinux.org/9/ALSA-2026-19353.html 
                        │      │                  ├ [27]: https://errata.rockylinux.org/RLSA-2026:23228 
                        │      │                  ├ [28]: https://go.dev/cl/763761 
                        │      │                  ├ [29]: https://go.dev/issue/78293 
                        │      │                  ├ [30]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [31]: https://linux.oracle.com/cve/CVE-2026-32282.html 
                        │      │                  ├ [32]: https://linux.oracle.com/errata/ELSA-2026-25999.html 
                        │      │                  ├ [33]: https://nvd.nist.gov/vuln/detail/CVE-2026-32282 
                        │      │                  ├ [34]: https://pkg.go.dev/vuln/GO-2026-4864 
                        │      │                  ╰ [35]: https://www.cve.org/CVERecord?id=CVE-2026-32282 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.467Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:35:29.12Z 
                        ├ [26] ╭ VulnerabilityID : CVE-2026-32288 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4869 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32288 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7616b3ba10f68936e9255db697d81a82099bba836977807c5dee9
                        │      │                   5386329b0dc 
                        │      ├ Title           : archive/tar: golang: Go's archive/tar package: Denial of
                        │      │                   Service via maliciously-crafted archive 
                        │      ├ Description     : tar.Reader can allocate an unbounded amount of memory when
                        │      │                   reading a maliciously-crafted archive containing a large
                        │      │                   number of sparse regions encoded in the "old GNU sparse map"
                        │      │                    format. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ azure  : 2 
                        │      │                  ├ bitnami: 2 
                        │      │                  ├ nvd    : 2 
                        │      │                  ├ photon : 2 
                        │      │                  ├ redhat : 2 
                        │      │                  ╰ ubuntu : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 5.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 5.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:
                        │      │                            │           N/A:L 
                        │      │                            ╰ V3Score : 4.3 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-32288 
                        │      │                  ├ [1]: https://go.dev/cl/763766 
                        │      │                  ├ [2]: https://go.dev/issue/78301 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/0uYbvbPZ
                        │      │                  │      RWU 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-32288 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4869 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-32288 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.707Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:35:29.977Z 
                        ├ [27] ╭ VulnerabilityID : CVE-2026-32289 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4865 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32289 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5f85634b92306f500b3fdee2128c40dcb55790c4f194790eab8f7
                        │      │                   ad3df52dcb3 
                        │      ├ Title           : html/template: golang: html/template: Cross-Site Scripting
                        │      │                   (XSS) via improper context and brace depth tracking in JS
                        │      │                   template literals 
                        │      ├ Description     : Context was not properly tracked across template branches
                        │      │                   for JS template literals, leading to possibly incorrect
                        │      │                   escaping of content when branches were used. Additionally
                        │      │                   template actions within JS template literals did not
                        │      │                   properly track the brace depth, leading to incorrect
                        │      │                   escaping being applied. These issues could cause actions
                        │      │                   within JS template literals to be incorrectly or improperly
                        │      │                   escaped, leading to XSS vulnerabilities. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ bitnami: 2 
                        │      │                  ├ nvd    : 2 
                        │      │                  ├ photon : 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 5.4 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-32289 
                        │      │                  ├ [1]: https://go.dev/cl/763762 
                        │      │                  ├ [2]: https://go.dev/issue/78331 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/0uYbvbPZ
                        │      │                  │      RWU 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-32289 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4865 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-32289 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.82Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:35:30.123Z 
                        ├ [28] ╭ VulnerabilityID : CVE-2026-39823 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4982 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f6d9a179353828cd9047e69961d723ff04b27ea7d95cbe80c89bc
                        │      │                   c17dcaa25ad 
                        │      ├ Title           : html/template: golang: Go html/template: Cross-Site
                        │      │                   Scripting via improper URL escaping in meta tag content 
                        │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly escaped inside of a <meta> tag's <content>
                        │      │                   attribute. If the URL content were to insert ASCII
                        │      │                   whitespaces around the '=' rune inside of the <content>
                        │      │                   attribute, the escaper would fail to similarly escape it,
                        │      │                   leading to XSS. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
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
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39823 
                        │      │                  ├ [1]: https://go.dev/cl/769920 
                        │      │                  ├ [2]: https://go.dev/issue/78913 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2026-39823.html 
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-39823 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4982 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39823 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.29Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.473Z 
                        ├ [29] ╭ VulnerabilityID : CVE-2026-39825 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4976 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e4f06c0955864ede8962d5d26a79b229aa3dec57fe05dd5477ad0
                        │      │                   2741cb0eae4 
                        │      ├ Title           : net/http/httputil: golang: net/http/httputil: ReverseProxy
                        │      │                   forwards hidden query parameters, potentially bypassing
                        │      │                   security controls 
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
                        │      ├ Severity        : MEDIUM 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 2 
                        │      │                  ╰ redhat     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39825 
                        │      │                  ├ [1]: https://go.dev/cl/770541 
                        │      │                  ├ [2]: https://go.dev/issue/78948 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2026-39825.html 
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-39825 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4976 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39825 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.39Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.77Z 
                        ├ [30] ╭ VulnerabilityID : CVE-2026-39826 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4980 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7c0c42f685014c95459b125cc6d16cae2b8c7c17acb39f8345630
                        │      │                   58fb31cf418 
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
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4980 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39826 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.923Z 
                        ├ [31] ╭ VulnerabilityID : CVE-2026-42505 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5856 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:04703501b452859cc047348f9de0f318cf978f89e7927817f5eda
                        │      │                   41b4f41cbe5 
                        │      ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
                        │      │                    Encrypted Client Hello 
                        │      ├ Description     : Handshakes which used Encrypted Client Hello could be
                        │      │                   de-anonymized by a passive network observer due to a
                        │      │                   disclosure of pre-shared key identities in the unencrypted
                        │      │                   client hello. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-201 
                        │      ├ VendorSeverity   ╭ bitnami: 2 
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
                        ├ [32] ╭ VulnerabilityID : CVE-2026-42507 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5039 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                        │      │                  │         f7b5687b2443e5cccf74 
                        │      │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                        │      │                            a9931ea661da63126f54 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:055cd0e62cc3485547cbced36b24d8aa59b99ca0aebd29b40ec4b
                        │      │                   92c82ef8e60 
                        │      ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                        │      │                   error messages via input injection 
                        │      ├ Description     : When returning errors, functions in the net/textproto
                        │      │                   package would include its input as part of the error. This
                        │      │                   might allow an attacker to inject misleading content to
                        │      │                   errors that are printed or logged. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ rocky      : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-42507 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2484205 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [5] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42507 
                        │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
                        │      │                  ├ [8] : https://errata.rockylinux.org/RLSA-2026:29981 
                        │      │                  ├ [9] : https://go.dev/cl/777060 
                        │      │                  ├ [10]: https://go.dev/issue/79346 
                        │      │                  ├ [11]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [12]: https://linux.oracle.com/cve/CVE-2026-42507.html 
                        │      │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
                        │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                        │      │                  ├ [15]: https://pkg.go.dev/vuln/GO-2026-5039 
                        │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                        │      ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
                        ╰ [33] ╭ VulnerabilityID : CVE-2026-27139 
                               ├ VendorIDs        ─ [0]: GO-2026-4602 
                               ├ PkgID           : stdlib@v1.25.7 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                               │                  ╰ UID : 75587475cbb2f2ed 
                               ├ InstalledVersion: v1.25.7 
                               ├ FixedVersion    : 1.25.8, 1.26.1 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:dc029fb1661f910b668a216f659c9894bfa75001ae2a
                               │                  │         f7b5687b2443e5cccf74 
                               │                  ╰ DiffID: sha256:ee2a72669abf0dfaea085aed23aa9b7b66e4ebcdaa01
                               │                            a9931ea661da63126f54 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27139 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:e816f47509f4e48bcc2dc517a23788825b9ac8cabe714b84d95eb
                               │                   245fa5adfe1 
                               ├ Title           : os: FileInfo can escape from a Root in golang os module 
                               ├ Description     : On Unix platforms, when listing the contents of a directory
                               │                   using File.ReadDir or File.Readdir the returned FileInfo
                               │                   could reference a file outside of the Root in which the File
                               │                    was opened. The impact of this escape is limited to reading
                               │                    metadata provided by lstat from arbitrary locations on the
                               │                   filesystem without permitting reading or writing files
                               │                   outside the root. 
                               ├ Severity        : LOW 
                               ├ CweIDs           ─ [0]: CWE-22 
                               ├ VendorSeverity   ╭ amazon : 3 
                               │                  ├ azure  : 1 
                               │                  ├ bitnami: 1 
                               │                  ├ photon : 1 
                               │                  ╰ redhat : 1 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:
                               │                  │         │           N/A:N 
                               │                  │         ╰ V3Score : 2.5 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:
                               │                            │           N/A:N 
                               │                            ╰ V3Score : 2.5 
                               ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-27139 
                               │                  ├ [1]: https://go.dev/cl/749480 
                               │                  ├ [2]: https://go.dev/issue/77827 
                               │                  ├ [3]: https://groups.google.com/g/golang-announce/c/EdhZqrQ9
                               │                  │      8hk 
                               │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-27139 
                               │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4602 
                               │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-27139 
                               ├ PublishedDate   : 2026-03-06T22:16:01.07Z 
                               ╰ LastModifiedDate: 2026-06-17T10:26:44.23Z 
```

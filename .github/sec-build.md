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
│                             ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                             │                  │         6ca5d52b5e968fc34e6 
│                             │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                             │                            386b067d01335c3374d 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54515 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:3e02a3213f8733cc799e46e245c5b40253f97ba864dce5d46f4f9b
│                             │                   fe9c43cdf3 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:2e7103418be2e516f17d21f8f07ae15745743d19c0902ec566ca89
│                       │     │                   470b3c8d4d 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:060cd3dee451a18497039e2b9480aa88f144cdbde002fc274ebe5b
│                       │     │                   5a2a16dd8f 
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
│                             ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                             │                  │         6ca5d52b5e968fc34e6 
│                             │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                             │                            386b067d01335c3374d 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:c6cf1056973e4c79e50f45773c25480280fce130dbe508ea216aa0
│                             │                   bf020c26ac 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:c9169cd7e51f1badf2496c92e272bdbfc88b240e96bb68945c99cf
│                       │     │                   ea8c337b06 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ac618480dd6543d17ff76735689887aa8d8a4f402266fb5a398f4a
│                       │     │                   8d3fa5f818 
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
│                             ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                             │                  │         6ca5d52b5e968fc34e6 
│                             │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                             │                            386b067d01335c3374d 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:8370ae434a237fbd2b5dc79ca06e09cff9316af5e2a6891267bd25
│                             │                   b313c35f27 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:3f855e58b55ee9e6a5e079254dceee78d0ee266089d9592211ad35
│                       │     │                   3652745487 
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
│                       │     ╰ LastModifiedDate: 2026-07-13T14:16:24.74Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:859c592cc054f7b1c4b42381f563d566afd16a5de55c8d46fdd13f
│                       │     │                   4ceec12332 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-48096 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:c65e8f0312acdde636fb90643755bd3ac1b5a47411b82e803b2c5c
│                       │     │                   2f5e112187 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55689 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:b06c9e7e015699fa8e0a017c9e14c48b6ebe50b53e7415390a6af6
│                       │     │                   48519317e0 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55170 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:1df5aae67ab402683526dd8fe9d2f3cdf54480178d1687b44c76c5
│                       │     │                   2c38203a7c 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:eba265756a5aed54788e889e36931a4cb5c4dfd2696516b7dfe9b5
│                       │     │                   51bda28feb 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:d35dc77ff316f923f905a74ed40dcae1bbf85c68ed2c4bf90f918b
│                       │     │                   46a5b7af0b 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:63a52ca457773fec67c4b08adb4651c7a9d9408cc5c3e921f5c5da
│                       │     │                   5963e97b0c 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:dce4b887946c2d15a500dc5b9933a38f03a30d9c6bf96374a070a9
│                       │     │                   71c7e4781f 
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
│                       │     │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38495 
│                       │     │                  ├ [7] : https://go.dev/cl/797880 
│                       │     │                  ├ [8] : https://go.dev/issue/79005 
│                       │     │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Yp
│                       │     │                  │       5Sc 
│                       │     │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
│                       │     │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38878.html 
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
│                             ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                             │                  │         6ca5d52b5e968fc34e6 
│                             │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                             │                            386b067d01335c3374d 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:36bf7f94b001aacdc9ded1ad35d4c1fb93bfe1bb2d829dcbcdef19
│                             │                   5704946334 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:2e477edc8100891ad4671cbeb639cd20f7174eda5fc52f16888e81
│                       │     │                   72f66e1649 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:4589bd42a2833df00838070f93cc6f7902c831ca725b41420a88be
│                       │     │                   ebb9e97b14 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:4c312924ab899cbbd2a11d326f88cb639eef870a324b8d5d69780f
│                       │     │                   26a8f2ba88 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:03f348f69f0c370ec3e05b2d6f38e7f54b655c6955dbef4c992df4
│                       │     │                   8421038af2 
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
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
│                       │     │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:33574 
│                       │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:35832 
│                       │     │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:36317 
│                       │     │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │     │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │     │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:38995 
│                       │     │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:39005 
│                       │     │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │     │                  ├ [11]: https://bugzilla.redhat.com/2445356 
│                       │     │                  ├ [12]: https://bugzilla.redhat.com/2484207 
│                       │     │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2467822 
│                       │     │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │     │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-27145 
│                       │     │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                       │     │                  │       6-33811 
│                       │     │                  ├ [17]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
│                       │     │                  ├ [18]: https://errata.rockylinux.org/RLSA-2026:35832 
│                       │     │                  ├ [19]: https://go.dev/cl/783621 
│                       │     │                  ├ [20]: https://go.dev/issue/79694 
│                       │     │                  ├ [21]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │     │                  │       cKw 
│                       │     │                  ├ [22]: https://linux.oracle.com/cve/CVE-2026-27145.html 
│                       │     │                  ├ [23]: https://linux.oracle.com/errata/ELSA-2026-36317.html 
│                       │     │                  ├ [24]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ├ [25]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     │                  ├ [26]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-27145.json 
│                       │     │                  ╰ [27]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-07-14T12:16:57.193Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-39822 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6b7ce0c806c32a1554334232356cffb858921015a1cf0c022ef089
│                       │     │                   13b31890f7 
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
│                       │     │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38495 
│                       │     │                  ├ [7] : https://go.dev/cl/797880 
│                       │     │                  ├ [8] : https://go.dev/issue/79005 
│                       │     │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Yp
│                       │     │                  │       5Sc 
│                       │     │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
│                       │     │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38878.html 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:7ce69be9fd676d4234d6b9020120222808dd0779de2f667b12bafa
│                       │     │                   0af8c34a3d 
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
│                       │     ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                       │     │                  │         6ca5d52b5e968fc34e6 
│                       │     │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                       │     │                            386b067d01335c3374d 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:62e9cb3e4b232fe7f0335aef05c623e1187b07ae5c68c6e8a535f0
│                       │     │                   dbf6cd983f 
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
│                             ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b20
│                             │                  │         6ca5d52b5e968fc34e6 
│                             │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba44
│                             │                            386b067d01335c3374d 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:e37b6f15b9d8cebfe35cfed217e3d7697f40bb3e1ce1b89da92b7d
│                             │                   b2ce920c09 
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
│                             │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-202
│                             │                  │       6-42507 
│                             │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
│                             │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:29980 
│                             │                  ├ [7] : https://go.dev/cl/777060 
│                             │                  ├ [8] : https://go.dev/issue/79346 
│                             │                  ├ [9] : https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                             │                  │       cKw 
│                             │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-42507.html 
│                             │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                             │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                             │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-5039 
│                             │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-29181 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:95a650103a8fa2a7e30a205e2416d7e9d74116a946d318816f9c5
                        │      │                   55ddbee2819 
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
                        │      ╰ LastModifiedDate: 2026-06-30T03:18:08.56Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2026-39883 
                        │      ├ VendorIDs        ─ [0]: GHSA-hfvc-g4fc-pqhx 
                        │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.40.0 
                        │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.40.0 
                        │      │                  ╰ UID : a801227131958a6e 
                        │      ├ InstalledVersion: v1.40.0 
                        │      ├ FixedVersion    : 1.43.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:1efd58e76ad134ca295ac7259b3bf4df3940172ad48b7e71a5e0d
                        │      │                   96baf69c52c 
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
                        │      ╰ LastModifiedDate: 2026-07-10T12:16:46.057Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-25681 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5029 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:270835968cdd03cbb80443acdbe2c7c74d712abfb469af9512a00
                        │      │                   3824e9bcf7a 
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
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39830 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [24]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [25]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [26]: https://errata.rockylinux.org/RLSA-2026:37072 
                        │      │                  ├ [27]: https://go.dev/cl/781703 
                        │      │                  ├ [28]: https://go.dev/issue/79574 
                        │      │                  ├ [29]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [30]: https://linux.oracle.com/cve/CVE-2026-25681.html 
                        │      │                  ├ [31]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [32]: https://nvd.nist.gov/vuln/detail/CVE-2026-25681 
                        │      │                  ├ [33]: https://pkg.go.dev/vuln/GO-2026-5029 
                        │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-25681 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:6153ec545410d4a283054ecdb3538c0060daeedbc46268f482560
                        │      │                   a1b5a5c955d 
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
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [16]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39830 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [24]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [25]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [26]: https://errata.rockylinux.org/RLSA-2026:37072 
                        │      │                  ├ [27]: https://go.dev/cl/781685 
                        │      │                  ├ [28]: https://go.dev/issue/79575 
                        │      │                  ├ [29]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [30]: https://linux.oracle.com/cve/CVE-2026-27136.html 
                        │      │                  ├ [31]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [32]: https://nvd.nist.gov/vuln/detail/CVE-2026-27136 
                        │      │                  ├ [33]: https://pkg.go.dev/vuln/GO-2026-5030 
                        │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-27136 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3e14fb912f62e21a61bebe1b81f77b5643883c4632bbe6352eb4f
                        │      │                   895b5dcdd35 
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
                        │      ╰ LastModifiedDate: 2026-07-10T12:16:41.55Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:31449a3de78061c3040abde39bff6d85ecb87f4934dda5ff71bc1
                        │      │                   bfb2dbc0807 
                        │      ├ Title           : golang.org/x/net/idna: golang: golang.org/x/net/idna:
                        │      │                   Privilege escalation via incorrect Punycode label
                        │      │                   processing 
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
                        │      │                  ├ [44]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [45]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [46]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [47]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39821 
                        │      │                  ├ [48]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [49]: https://errata.rockylinux.org/RLSA-2026:35831 
                        │      │                  ├ [50]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [51]: https://go.dev/cl/767220 
                        │      │                  ├ [52]: https://go.dev/issue/78760 
                        │      │                  ├ [53]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [54]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [55]: https://linux.oracle.com/errata/ELSA-2026-37435.html 
                        │      │                  ├ [56]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [57]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [58]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39821.json 
                        │      │                  ├ [59]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [60]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-07-14T12:17:02.053Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:709983c514bacececae7cb56e2167db48bf9db10c974ff6c2b1d8
                        │      │                   f31fb6b3bad 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:608505cee75080cebecb0c363e8feab80abd1008f6332ebb9a370
                        │      │                   d31e353c750 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:63182590be9dac63cf9a9bbf36bde3b8eb24fe4aa500825e6934e
                        │      │                   f701ebd8cc1 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:babf7c2d1caf2e57f7923c3857de2fe3855d7d2db6e75b9c1617f
                        │      │                   91bcb6c010a 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:94d68b1a0adcc350e0596f13ee35f24616f1d1a13e6f58f53b75a
                        │      │                   cdb22fee6db 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:36bcffa538d5e8f2a0fb76951731250be15d8d915f5e303ccee34
                        │      │                   ec804b7e7cb 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25679 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d1381df3fc6c97ed64215de7e066a1be641a0161e800c92343cfe
                        │      │                   f53c52356cf 
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
                        │      │                  ├ [139]: https://access.redhat.com/errata/RHSA-2026:5110 
                        │      │                  ├ [140]: https://access.redhat.com/errata/RHSA-2026:5549 
                        │      │                  ├ [141]: https://access.redhat.com/errata/RHSA-2026:5941 
                        │      │                  ├ [142]: https://access.redhat.com/errata/RHSA-2026:5942 
                        │      │                  ├ [143]: https://access.redhat.com/errata/RHSA-2026:5943 
                        │      │                  ├ [144]: https://access.redhat.com/errata/RHSA-2026:5944 
                        │      │                  ├ [145]: https://access.redhat.com/errata/RHSA-2026:6341 
                        │      │                  ├ [146]: https://access.redhat.com/errata/RHSA-2026:6344 
                        │      │                  ├ [147]: https://access.redhat.com/errata/RHSA-2026:6382 
                        │      │                  ├ [148]: https://access.redhat.com/errata/RHSA-2026:6383 
                        │      │                  ├ [149]: https://access.redhat.com/errata/RHSA-2026:6388 
                        │      │                  ├ [150]: https://access.redhat.com/errata/RHSA-2026:6564 
                        │      │                  ├ [151]: https://access.redhat.com/errata/RHSA-2026:6720 
                        │      │                  ├ [152]: https://access.redhat.com/errata/RHSA-2026:6802 
                        │      │                  ├ [153]: https://access.redhat.com/errata/RHSA-2026:6949 
                        │      │                  ├ [154]: https://access.redhat.com/errata/RHSA-2026:7005 
                        │      │                  ├ [155]: https://access.redhat.com/errata/RHSA-2026:7009 
                        │      │                  ├ [156]: https://access.redhat.com/errata/RHSA-2026:7011 
                        │      │                  ├ [157]: https://access.redhat.com/errata/RHSA-2026:7259 
                        │      │                  ├ [158]: https://access.redhat.com/errata/RHSA-2026:7291 
                        │      │                  ├ [159]: https://access.redhat.com/errata/RHSA-2026:7315 
                        │      │                  ├ [160]: https://access.redhat.com/errata/RHSA-2026:7328 
                        │      │                  ├ [161]: https://access.redhat.com/errata/RHSA-2026:7385 
                        │      │                  ├ [162]: https://access.redhat.com/errata/RHSA-2026:7665 
                        │      │                  ├ [163]: https://access.redhat.com/errata/RHSA-2026:7669 
                        │      │                  ├ [164]: https://access.redhat.com/errata/RHSA-2026:7674 
                        │      │                  ├ [165]: https://access.redhat.com/errata/RHSA-2026:7833 
                        │      │                  ├ [166]: https://access.redhat.com/errata/RHSA-2026:7834 
                        │      │                  ├ [167]: https://access.redhat.com/errata/RHSA-2026:7876 
                        │      │                  ├ [168]: https://access.redhat.com/errata/RHSA-2026:7877 
                        │      │                  ├ [169]: https://access.redhat.com/errata/RHSA-2026:7878 
                        │      │                  ├ [170]: https://access.redhat.com/errata/RHSA-2026:7879 
                        │      │                  ├ [171]: https://access.redhat.com/errata/RHSA-2026:7883 
                        │      │                  ├ [172]: https://access.redhat.com/errata/RHSA-2026:7992 
                        │      │                  ├ [173]: https://access.redhat.com/errata/RHSA-2026:8151 
                        │      │                  ├ [174]: https://access.redhat.com/errata/RHSA-2026:8167 
                        │      │                  ├ [175]: https://access.redhat.com/errata/RHSA-2026:8314 
                        │      │                  ├ [176]: https://access.redhat.com/errata/RHSA-2026:8322 
                        │      │                  ├ [177]: https://access.redhat.com/errata/RHSA-2026:8324 
                        │      │                  ├ [178]: https://access.redhat.com/errata/RHSA-2026:8337 
                        │      │                  ├ [179]: https://access.redhat.com/errata/RHSA-2026:8338 
                        │      │                  ├ [180]: https://access.redhat.com/errata/RHSA-2026:8433 
                        │      │                  ├ [181]: https://access.redhat.com/errata/RHSA-2026:8434 
                        │      │                  ├ [182]: https://access.redhat.com/errata/RHSA-2026:8456 
                        │      │                  ├ [183]: https://access.redhat.com/errata/RHSA-2026:8483 
                        │      │                  ├ [184]: https://access.redhat.com/errata/RHSA-2026:8484 
                        │      │                  ├ [185]: https://access.redhat.com/errata/RHSA-2026:8490 
                        │      │                  ├ [186]: https://access.redhat.com/errata/RHSA-2026:8491 
                        │      │                  ├ [187]: https://access.redhat.com/errata/RHSA-2026:8493 
                        │      │                  ├ [188]: https://access.redhat.com/errata/RHSA-2026:8840 
                        │      │                  ├ [189]: https://access.redhat.com/errata/RHSA-2026:8841 
                        │      │                  ├ [190]: https://access.redhat.com/errata/RHSA-2026:8842 
                        │      │                  ├ [191]: https://access.redhat.com/errata/RHSA-2026:8845 
                        │      │                  ├ [192]: https://access.redhat.com/errata/RHSA-2026:8847 
                        │      │                  ├ [193]: https://access.redhat.com/errata/RHSA-2026:8848 
                        │      │                  ├ [194]: https://access.redhat.com/errata/RHSA-2026:8849 
                        │      │                  ├ [195]: https://access.redhat.com/errata/RHSA-2026:8851 
                        │      │                  ├ [196]: https://access.redhat.com/errata/RHSA-2026:8852 
                        │      │                  ├ [197]: https://access.redhat.com/errata/RHSA-2026:8853 
                        │      │                  ├ [198]: https://access.redhat.com/errata/RHSA-2026:8855 
                        │      │                  ├ [199]: https://access.redhat.com/errata/RHSA-2026:8856 
                        │      │                  ├ [200]: https://access.redhat.com/errata/RHSA-2026:8860 
                        │      │                  ├ [201]: https://access.redhat.com/errata/RHSA-2026:8877 
                        │      │                  ├ [202]: https://access.redhat.com/errata/RHSA-2026:8878 
                        │      │                  ├ [203]: https://access.redhat.com/errata/RHSA-2026:8879 
                        │      │                  ├ [204]: https://access.redhat.com/errata/RHSA-2026:8881 
                        │      │                  ├ [205]: https://access.redhat.com/errata/RHSA-2026:8882 
                        │      │                  ├ [206]: https://access.redhat.com/errata/RHSA-2026:8930 
                        │      │                  ├ [207]: https://access.redhat.com/errata/RHSA-2026:8931 
                        │      │                  ├ [208]: https://access.redhat.com/errata/RHSA-2026:8949 
                        │      │                  ├ [209]: https://access.redhat.com/errata/RHSA-2026:9043 
                        │      │                  ├ [210]: https://access.redhat.com/errata/RHSA-2026:9044 
                        │      │                  ├ [211]: https://access.redhat.com/errata/RHSA-2026:9052 
                        │      │                  ├ [212]: https://access.redhat.com/errata/RHSA-2026:9090 
                        │      │                  ├ [213]: https://access.redhat.com/errata/RHSA-2026:9093 
                        │      │                  ├ [214]: https://access.redhat.com/errata/RHSA-2026:9094 
                        │      │                  ├ [215]: https://access.redhat.com/errata/RHSA-2026:9097 
                        │      │                  ├ [216]: https://access.redhat.com/errata/RHSA-2026:9098 
                        │      │                  ├ [217]: https://access.redhat.com/errata/RHSA-2026:9108 
                        │      │                  ├ [218]: https://access.redhat.com/errata/RHSA-2026:9109 
                        │      │                  ├ [219]: https://access.redhat.com/errata/RHSA-2026:9385 
                        │      │                  ├ [220]: https://access.redhat.com/errata/RHSA-2026:9434 
                        │      │                  ├ [221]: https://access.redhat.com/errata/RHSA-2026:9435 
                        │      │                  ├ [222]: https://access.redhat.com/errata/RHSA-2026:9436 
                        │      │                  ├ [223]: https://access.redhat.com/errata/RHSA-2026:9439 
                        │      │                  ├ [224]: https://access.redhat.com/errata/RHSA-2026:9440 
                        │      │                  ├ [225]: https://access.redhat.com/errata/RHSA-2026:9448 
                        │      │                  ├ [226]: https://access.redhat.com/errata/RHSA-2026:9453 
                        │      │                  ├ [227]: https://access.redhat.com/errata/RHSA-2026:9461 
                        │      │                  ├ [228]: https://access.redhat.com/errata/RHSA-2026:9695 
                        │      │                  ├ [229]: https://access.redhat.com/errata/RHSA-2026:9742 
                        │      │                  ├ [230]: https://access.redhat.com/errata/RHSA-2026:9872 
                        │      │                  ├ [231]: https://access.redhat.com/security/cve/CVE-2026-25679 
                        │      │                  ├ [232]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [233]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [234]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [235]: https://errata.almalinux.org/9/ALSA-2026-9044.html 
                        │      │                  ├ [236]: https://errata.rockylinux.org/RLSA-2026:8456 
                        │      │                  ├ [237]: https://go.dev/cl/752180 
                        │      │                  ├ [238]: https://go.dev/issue/77578 
                        │      │                  ├ [239]: https://groups.google.com/g/golang-announce/c/EdhZqr
                        │      │                  │        Q98hk 
                        │      │                  ├ [240]: https://linux.oracle.com/cve/CVE-2026-25679.html 
                        │      │                  ├ [241]: https://linux.oracle.com/errata/ELSA-2026-9044.html 
                        │      │                  ├ [242]: https://nvd.nist.gov/vuln/detail/CVE-2026-25679 
                        │      │                  ├ [243]: https://pkg.go.dev/vuln/GO-2026-4601 
                        │      │                  ├ [244]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-25679.json 
                        │      │                  ╰ [245]: https://www.cve.org/CVERecord?id=CVE-2026-25679 
                        │      ├ PublishedDate   : 2026-03-06T22:16:00.72Z 
                        │      ╰ LastModifiedDate: 2026-07-10T12:16:35.637Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:ffe146b1ad5ed511c25b7dc7c0925df549a7eeccb0bd0107bff42
                        │      │                   1b3eae17f60 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:35832 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:36317 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:36648 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:38995 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:39005 
                        │      │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2467822 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-33811 
                        │      │                  ├ [17]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
                        │      │                  ├ [18]: https://errata.rockylinux.org/RLSA-2026:35832 
                        │      │                  ├ [19]: https://go.dev/cl/783621 
                        │      │                  ├ [20]: https://go.dev/issue/79694 
                        │      │                  ├ [21]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [22]: https://linux.oracle.com/cve/CVE-2026-27145.html 
                        │      │                  ├ [23]: https://linux.oracle.com/errata/ELSA-2026-36317.html 
                        │      │                  ├ [24]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [25]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [26]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [27]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-07-14T12:16:57.193Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-32280 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4947 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32280 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:30d5dfb500e1af35d645e64319df975b2d86bd74665b7da8ece62
                        │      │                   33f9efaea87 
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
                        │      │                  ├ [129]: https://access.redhat.com/errata/RHSA-2026:9385 
                        │      │                  ├ [130]: https://access.redhat.com/security/cve/CVE-2026-32280 
                        │      │                  ├ [131]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [132]: https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [133]: https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [134]: https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [135]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [136]: https://bugzilla.redhat.com/show_bug.cgi?id=2455470 
                        │      │                  ├ [137]: https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [138]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [139]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [140]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [141]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32280 
                        │      │                  ├ [142]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32281 
                        │      │                  ├ [143]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32283 
                        │      │                  ├ [144]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-34986 
                        │      │                  ├ [145]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [146]: https://errata.rockylinux.org/RLSA-2026:33722 
                        │      │                  ├ [147]: https://go.dev/cl/758320 
                        │      │                  ├ [148]: https://go.dev/issue/78282 
                        │      │                  ├ [149]: https://groups.google.com/g/golang-announce/c/0uYbvb
                        │      │                  │        PZRWU 
                        │      │                  ├ [150]: https://linux.oracle.com/cve/CVE-2026-32280.html 
                        │      │                  ├ [151]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [152]: https://nvd.nist.gov/vuln/detail/CVE-2026-32280 
                        │      │                  ├ [153]: https://pkg.go.dev/vuln/GO-2026-4947 
                        │      │                  ├ [154]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-32280.json 
                        │      │                  ╰ [155]: https://www.cve.org/CVERecord?id=CVE-2026-32280 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.247Z 
                        │      ╰ LastModifiedDate: 2026-07-10T12:16:38.577Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2026-32281 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4946 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32281 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4b7155ff11fe83276128e5aa3513f09378b50edea658a365141c2
                        │      │                   dca45cea4a0 
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
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2455470 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [11]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [12]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [13]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32281 
                        │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-34986 
                        │      │                  ├ [16]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [17]: https://errata.rockylinux.org/RLSA-2026:33722 
                        │      │                  ├ [18]: https://go.dev/cl/758061 
                        │      │                  ├ [19]: https://go.dev/issue/78281 
                        │      │                  ├ [20]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [21]: https://linux.oracle.com/cve/CVE-2026-32281.html 
                        │      │                  ├ [22]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [23]: https://nvd.nist.gov/vuln/detail/CVE-2026-32281 
                        │      │                  ├ [24]: https://pkg.go.dev/vuln/GO-2026-4946 
                        │      │                  ╰ [25]: https://www.cve.org/CVERecord?id=CVE-2026-32281 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32283 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4b7ac23872ddfbdd6f7837f84bda56ee0432a35eadd9397c3efc0
                        │      │                   1383c18ffb0 
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
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:7291 
                        │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:7385 
                        │      │                  ├ [93] : https://access.redhat.com/security/cve/CVE-2026-32283 
                        │      │                  ├ [94] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [95] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [96] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [97] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [98] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [99] : https://bugzilla.redhat.com/show_bug.cgi?id=2455470 
                        │      │                  ├ [100]: https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [101]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [102]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [103]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [104]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32280 
                        │      │                  ├ [105]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32281 
                        │      │                  ├ [106]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32283 
                        │      │                  ├ [107]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-34986 
                        │      │                  ├ [108]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [109]: https://errata.rockylinux.org/RLSA-2026:33722 
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
                        │      ╰ LastModifiedDate: 2026-07-09T13:16:56.95Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2026-33811 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4981 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5859723988edcda1a6553c64cb47177cb3a00c7ba2c0e8d08450d
                        │      │                   25f03f56319 
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
                        │      │                  ├ [24]: https://access.redhat.com/security/cve/CVE-2026-33811 
                        │      │                  ├ [25]: https://bugzilla.redhat.com/2467822 
                        │      │                  ├ [26]: https://bugzilla.redhat.com/show_bug.cgi?id=2467822 
                        │      │                  ├ [27]: https://bugzilla.redhat.com/show_bug.cgi?id=2480680 
                        │      │                  ├ [28]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [29]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-33811 
                        │      │                  ├ [30]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [31]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [32]: https://errata.almalinux.org/9/ALSA-2026-36617.html 
                        │      │                  ├ [33]: https://errata.rockylinux.org/RLSA-2026:38504 
                        │      │                  ├ [34]: https://go.dev/cl/767860 
                        │      │                  ├ [35]: https://go.dev/issue/78803 
                        │      │                  ├ [36]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [37]: https://linux.oracle.com/cve/CVE-2026-33811.html 
                        │      │                  ├ [38]: https://linux.oracle.com/errata/ELSA-2026-36617.html 
                        │      │                  ├ [39]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ├ [40]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      │                  ├ [41]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33811.json 
                        │      │                  ╰ [42]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
                        │      ╰ LastModifiedDate: 2026-07-14T12:16:59.567Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8f76eea26ea001b5c2077d7f9766e29e523cbb7121bb15fab499f
                        │      │                   bbb02485dcc 
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
                        │      ╰ LastModifiedDate: 2026-07-10T12:16:41.55Z 
                        ├ [19] ╭ VulnerabilityID : CVE-2026-39820 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4986 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:50462ce7f330defa4bd482cbd6fc85720778242391b1954c8f71c
                        │      │                   9042f376f32 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:33120 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:33123 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:33142 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33150 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36625 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36754 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-39820 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2467820 
                        │      │                  ├ [12]: https://go.dev/cl/759940 
                        │      │                  ├ [13]: https://go.dev/issue/78566 
                        │      │                  ├ [14]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [15]: https://linux.oracle.com/cve/CVE-2026-39820.html 
                        │      │                  ├ [16]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ├ [18]: https://pkg.go.dev/vuln/GO-2026-4986 
                        │      │                  ├ [19]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39820.json 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2026-39820 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
                        │      ╰ LastModifiedDate: 2026-07-14T12:17:01.753Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2026-39822 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4970 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4cbdb09de46d48b21515a6326f8e28afc3ee1e0de68efafe7dd50
                        │      │                   8ca83415a4d 
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
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:38495 
                        │      │                  ├ [7] : https://go.dev/cl/797880 
                        │      │                  ├ [8] : https://go.dev/issue/79005 
                        │      │                  ├ [9] : https://groups.google.com/g/golang-announce/c/OrmQE_Y
                        │      │                  │       p5Sc 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-39822.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-38878.html 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:a6133e7b3cf11c7e656a49bb01568d2e692582342e13f62e94f3f
                        │      │                   8ea5718383e 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e12bc0e6f61b82916b65fb372867fc8fe2beabee21ea0748f756c
                        │      │                   db6ae6082de 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:33120 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:33123 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:33142 
                        │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:33150 
                        │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:36319 
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:36625 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36754 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36797 
                        │      │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-42499 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2467809 
                        │      │                  ├ [12]: https://go.dev/cl/771520 
                        │      │                  ├ [13]: https://go.dev/issue/78987 
                        │      │                  ├ [14]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [15]: https://linux.oracle.com/cve/CVE-2026-42499.html 
                        │      │                  ├ [16]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ├ [18]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      │                  ├ [19]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-42499.json 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2026-42499 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-07-14T12:17:05.91Z 
                        ├ [23] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c92b80332883707612ae8aadcd2732a25dedf1ef142168d4cff39
                        │      │                   9f17cf84432 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27142 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c639f155b9dafe6d504212c6264b7c18d0cb9e17e51a6ec4635ba
                        │      │                   a6ed9eb41c8 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32282 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:945fb12e8ba73a4e16a337f060ba17ee4acaad7c391a9227436ba
                        │      │                   6f6d93c0cf0 
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
                        │      │                  ├ oracle-oval: 3 
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
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456336 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32282 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [18]: https://errata.almalinux.org/9/ALSA-2026-19353.html 
                        │      │                  ├ [19]: https://errata.rockylinux.org/RLSA-2026:16875 
                        │      │                  ├ [20]: https://go.dev/cl/763761 
                        │      │                  ├ [21]: https://go.dev/issue/78293 
                        │      │                  ├ [22]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [23]: https://linux.oracle.com/cve/CVE-2026-32282.html 
                        │      │                  ├ [24]: https://linux.oracle.com/errata/ELSA-2026-19352.html 
                        │      │                  ├ [25]: https://nvd.nist.gov/vuln/detail/CVE-2026-32282 
                        │      │                  ├ [26]: https://pkg.go.dev/vuln/GO-2026-4864 
                        │      │                  ╰ [27]: https://www.cve.org/CVERecord?id=CVE-2026-32282 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32288 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:a671ddf2dfb555a850f0778accc9aa95fd10e5ac4009322c749f0
                        │      │                   e82d1a28ba7 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32289 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e5f16842e0f92bd48777ea3593893b8eb538a3a59996fced5e543
                        │      │                   57dad8dee49 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d20bb450500102dd6fc20e38f8abd416702bcb24e5621e96eacf3
                        │      │                   9cd702bd122 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d2b6cf7657c1a115768e5b35f8654186619637027ecf8c591b035
                        │      │                   7529158a026 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f3f64c303b9393a3eea6727f13e7d35b173773f868e981722f829
                        │      │                   0175f3cd028 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:bd82e662bd653290421e1c2f46fa9cbb48848481357823bdb299b
                        │      │                   ffd557a4eb3 
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
                        │      ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                        │      │                  │         06ca5d52b5e968fc34e6 
                        │      │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                        │      │                            4386b067d01335c3374d 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:19c79eb3b74f72fe35e36320a7999c24d7696c79a64ff1a295d74
                        │      │                   062f5dadc98 
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
                        │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42507 
                        │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:29980 
                        │      │                  ├ [7] : https://go.dev/cl/777060 
                        │      │                  ├ [8] : https://go.dev/issue/79346 
                        │      │                  ├ [9] : https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-42507.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
                        │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                        │      │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-5039 
                        │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
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
                               ├ Layer            ╭ Digest: sha256:840043b9530e7462465bf30e67e9989df7348ca185b2
                               │                  │         06ca5d52b5e968fc34e6 
                               │                  ╰ DiffID: sha256:116f6a8282ac9e3f6b8491545871beed76b5cb446ba4
                               │                            4386b067d01335c3374d 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27139 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:8de0d374ae235935bed3d2e0aaf041b3bc51f01419ac75430e094
                               │                   08ee8121444 
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

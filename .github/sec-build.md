````yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.23.0_alpha20250612) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target: Java 
│     ├ Class : lang-pkgs 
│     ╰ Type  : jar 
├ [2] ╭ Target: Node.js 
│     ├ Class : lang-pkgs 
│     ╰ Type  : node-pkg 
├ [3] ╭ Target: Python 
│     ├ Class : lang-pkgs 
│     ╰ Type  : python-pkg 
├ [4] ╭ Target         : usr/bin/prometheus 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-22874 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : d7a45da0b76d3d81 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                       │     │                  │         597c60644656c8309c8 
│                       │     │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                       │     │                            8498c532a6781aebf71 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : crypto/x509: Usage of ExtKeyUsageAny disables policy
│                       │     │                   validation in crypto/x509 
│                       │     ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
│                       │     │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
│                       │     │                   This only affected certificate chains which contain policy
│                       │     │                   graphs, which are rather uncommon. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H
│                       │     │                  │         │           /A:N 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2025-22874 
│                       │     │                  ├ [1]: https://go.dev/cl/670375 
│                       │     │                  ├ [2]: https://go.dev/issue/73612 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-22874 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2025-3749 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2025-22874 
│                       │     ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2025-0913 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : d7a45da0b76d3d81 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                       │     │                  │         597c60644656c8309c8 
│                       │     │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                       │     │                            8498c532a6781aebf71 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-0913 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows
│                       │     │                   in os in syscall 
│                       │     ├ Description     : os.OpenFile(path, os.O_CREATE|O_EXCL) behaved differently on
│                       │     │                   Unix and Windows systems when the target path was a dangling
│                       │     │                   symlink. On Unix systems, OpenFile with O_CREATE and O_EXCL
│                       │     │                   flags never follows symlinks. On Windows, when the target
│                       │     │                   path was a symlink to a nonexistent location, OpenFile would
│                       │     │                   create a file in that location. OpenFile now always returns
│                       │     │                   an error when the O_CREATE and O_EXCL flags are both set and
│                       │     │                   the target path is a symlink. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ bitnami: 2 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 5.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/672396 
│                       │     │                  ├ [1]: https://go.dev/issue/73702 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2025-0913 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2025-3750 
│                       │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2025-4673 
│                             ├ PkgID           : stdlib@v1.24.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                             │                  ╰ UID : d7a45da0b76d3d81 
│                             ├ InstalledVersion: v1.24.3 
│                             ├ FixedVersion    : 1.23.10, 1.24.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                             │                  │         597c60644656c8309c8 
│                             │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                             │                            8498c532a6781aebf71 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Title           : net/http: Sensitive headers not cleared on cross-origin
│                             │                   redirect in net/http 
│                             ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
│                             │                   on cross-origin redirects potentially leaking sensitive
│                             │                   information. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ bitnami: 2 
│                             │                  ├ redhat : 2 
│                             │                  ╰ ubuntu : 2 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N
│                             │                  │         │           /A:N 
│                             │                  │         ╰ V3Score : 6.8 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 6.8 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2025-4673 
│                             │                  ├ [1]: https://go.dev/cl/679257 
│                             │                  ├ [2]: https://go.dev/issue/73816 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-4673 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2025-3751 
│                             │                  ├ [6]: https://ubuntu.com/security/notices/USN-7574-1 
│                             │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
│                             ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
│                             ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-22874 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : edbc862110f114c1 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                       │     │                  │         597c60644656c8309c8 
│                       │     │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                       │     │                            8498c532a6781aebf71 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : crypto/x509: Usage of ExtKeyUsageAny disables policy
│                       │     │                   validation in crypto/x509 
│                       │     ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
│                       │     │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
│                       │     │                   This only affected certificate chains which contain policy
│                       │     │                   graphs, which are rather uncommon. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H
│                       │     │                  │         │           /A:N 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2025-22874 
│                       │     │                  ├ [1]: https://go.dev/cl/670375 
│                       │     │                  ├ [2]: https://go.dev/issue/73612 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-22874 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2025-3749 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2025-22874 
│                       │     ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2025-0913 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : edbc862110f114c1 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                       │     │                  │         597c60644656c8309c8 
│                       │     │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                       │     │                            8498c532a6781aebf71 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-0913 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows
│                       │     │                   in os in syscall 
│                       │     ├ Description     : os.OpenFile(path, os.O_CREATE|O_EXCL) behaved differently on
│                       │     │                   Unix and Windows systems when the target path was a dangling
│                       │     │                   symlink. On Unix systems, OpenFile with O_CREATE and O_EXCL
│                       │     │                   flags never follows symlinks. On Windows, when the target
│                       │     │                   path was a symlink to a nonexistent location, OpenFile would
│                       │     │                   create a file in that location. OpenFile now always returns
│                       │     │                   an error when the O_CREATE and O_EXCL flags are both set and
│                       │     │                   the target path is a symlink. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ bitnami: 2 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 5.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/672396 
│                       │     │                  ├ [1]: https://go.dev/issue/73702 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2025-0913 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2025-3750 
│                       │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2025-4673 
│                             ├ PkgID           : stdlib@v1.24.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                             │                  ╰ UID : edbc862110f114c1 
│                             ├ InstalledVersion: v1.24.3 
│                             ├ FixedVersion    : 1.23.10, 1.24.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                             │                  │         597c60644656c8309c8 
│                             │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                             │                            8498c532a6781aebf71 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Title           : net/http: Sensitive headers not cleared on cross-origin
│                             │                   redirect in net/http 
│                             ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
│                             │                   on cross-origin redirects potentially leaking sensitive
│                             │                   information. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ bitnami: 2 
│                             │                  ├ redhat : 2 
│                             │                  ╰ ubuntu : 2 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N
│                             │                  │         │           /A:N 
│                             │                  │         ╰ V3Score : 6.8 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 6.8 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2025-4673 
│                             │                  ├ [1]: https://go.dev/cl/679257 
│                             │                  ├ [2]: https://go.dev/issue/73816 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-4673 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2025-3751 
│                             │                  ├ [6]: https://ubuntu.com/security/notices/USN-7574-1 
│                             │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
│                             ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
│                             ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GHSA-2x5j-vhc8-9cwm 
│                             ├ PkgID           : github.com/cloudflare/circl@v1.6.0 
│                             ├ PkgName         : github.com/cloudflare/circl 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/cloudflare/circl@v1.6.0 
│                             │                  ╰ UID : ad3bafe31fc946d5 
│                             ├ InstalledVersion: v1.6.0 
│                             ├ FixedVersion    : 1.6.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:af2b7c0c6de499de06c69718fcea68ec55f41d5666008
│                             │                  │         597c60644656c8309c8 
│                             │                  ╰ DiffID: sha256:88deed176625ea74b9aa2cbfac91a9c5c4e8aa727e1f2
│                             │                            8498c532a6781aebf71 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-2x5j-vhc8-9cwm 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : CIRCL-Fourq: Missing and wrong validation can lead to
│                             │                   incorrect results 
│                             ├ Description     : ### Impact
│                             │                   The CIRCL implementation of FourQ fails to validate
│                             │                   user-supplied low-order points during Diffie-Hellman key
│                             │                   exchange, potentially allowing attackers to force the
│                             │                   identity point and compromise session security.
│                             │                   
│                             │                   Moreover, there is an incorrect point validation in
│                             │                   ScalarMult can lead to incorrect results in the isEqual
│                             │                   function and if a point is on the curve.
│                             │                   ### Patches
│                             │                   Version 1.6.1
│                             │                   (https://github.com/cloudflare/circl/tree/v1.6.1) mitigates
│                             │                   the identified issues.
│                             │                   We acknowledge Alon Livne (Botanica Software Labs) for the
│                             │                   reported findings. 
│                             ├ Severity        : LOW 
│                             ├ VendorSeverity   ─ ghsa: 1 
│                             ├ References       ╭ [0]: https://github.com/cloudflare/circl 
│                             │                  ├ [1]: https://github.com/cloudflare/circl/security/advisories
│                             │                  │      /GHSA-2x5j-vhc8-9cwm 
│                             │                  ╰ [2]: https://github.com/cloudflare/circl/tree/v1.6.1 
│                             ├ PublishedDate   : 2025-06-10T21:18:33Z 
│                             ╰ LastModifiedDate: 2025-06-10T21:18:33Z 
├ [7] ╭ Target: usr/share/grafana/bin/grafana-cli 
│     ├ Class : lang-pkgs 
│     ╰ Type  : gobinary 
╰ [8] ╭ Target: usr/share/grafana/bin/grafana-server 
      ├ Class : lang-pkgs 
      ╰ Type  : gobinary 
````

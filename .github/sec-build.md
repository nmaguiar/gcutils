````yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.22.0) 
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
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-4673 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : d7a45da0b76d3d81 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross- ... 
│                       │     ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross-origin redirects potentially leaking sensitive
│                       │     │                   information. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ubuntu: 2 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/679257 
│                       │     │                  ├ [1]: https://go.dev/issue/73816 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [3]: https://pkg.go.dev/vuln/GO-2025-3751 
│                       │     │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
│                       │     ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2025-0913 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : d7a45da0b76d3d81 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
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
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/672396 
│                       │     │                  ├ [1]: https://go.dev/issue/73702 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3750 
│                       │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2025-22874 
│                             ├ PkgID           : stdlib@v1.24.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                             │                  ╰ UID : d7a45da0b76d3d81 
│                             ├ InstalledVersion: v1.24.3 
│                             ├ FixedVersion    : 1.23.10, 1.24.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                             │                  │         efd6ad4bae877649b2e 
│                             │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                             │                            ef2ce9c5f531ec3064f 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Title           : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsag ... 
│                             ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
│                             │                   This only affected certificate chains which contain policy
│                             │                   graphs, which are rather uncommon. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/670375 
│                             │                  ├ [1]: https://go.dev/issue/73612 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3749 
│                             ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
│                             ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-4673 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : edbc862110f114c1 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross- ... 
│                       │     ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross-origin redirects potentially leaking sensitive
│                       │     │                   information. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ubuntu: 2 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/679257 
│                       │     │                  ├ [1]: https://go.dev/issue/73816 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [3]: https://pkg.go.dev/vuln/GO-2025-3751 
│                       │     │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
│                       │     ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2025-0913 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : edbc862110f114c1 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
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
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/672396 
│                       │     │                  ├ [1]: https://go.dev/issue/73702 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3750 
│                       │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2025-22874 
│                             ├ PkgID           : stdlib@v1.24.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                             │                  ╰ UID : edbc862110f114c1 
│                             ├ InstalledVersion: v1.24.3 
│                             ├ FixedVersion    : 1.23.10, 1.24.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                             │                  │         efd6ad4bae877649b2e 
│                             │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                             │                            ef2ce9c5f531ec3064f 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Title           : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsag ... 
│                             ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
│                             │                   This only affected certificate chains which contain policy
│                             │                   graphs, which are rather uncommon. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/670375 
│                             │                  ├ [1]: https://go.dev/issue/73612 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3749 
│                             ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
│                             ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GHSA-2x5j-vhc8-9cwm 
│                       │     ├ PkgID           : github.com/cloudflare/circl@v1.6.0 
│                       │     ├ PkgName         : github.com/cloudflare/circl 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/cloudflare/circl@v1.6.0 
│                       │     │                  ╰ UID : ad3bafe31fc946d5 
│                       │     ├ InstalledVersion: v1.6.0 
│                       │     ├ FixedVersion    : 1.6.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://github.com/advisories/GHSA-2x5j-vhc8-9cwm 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : CIRCL-Fourq: Missing and wrong validation can lead to
│                       │     │                   incorrect results 
│                       │     ├ Description     : ### Impact
│                       │     │                   The CIRCL implementation of FourQ fails to validate
│                       │     │                   user-supplied low-order points during Diffie-Hellman key
│                       │     │                   exchange, potentially allowing attackers to force the
│                       │     │                   identity point and compromise session security.
│                       │     │                   
│                       │     │                   Moreover, there is an incorrect point validation in
│                       │     │                   ScalarMult can lead to incorrect results in the isEqual
│                       │     │                   function and if a point is on the curve.
│                       │     │                   ### Patches
│                       │     │                   Version 1.6.1
│                       │     │                   (https://github.com/cloudflare/circl/tree/v1.6.1) mitigates
│                       │     │                   the identified issues.
│                       │     │                   We acknowledge Alon Livne (Botanica Software Labs) for the
│                       │     │                   reported findings. 
│                       │     ├ Severity        : LOW 
│                       │     ├ VendorSeverity   ─ ghsa: 1 
│                       │     ├ References       ╭ [0]: https://github.com/cloudflare/circl 
│                       │     │                  ├ [1]: https://github.com/cloudflare/circl/security/advisories
│                       │     │                  │      /GHSA-2x5j-vhc8-9cwm 
│                       │     │                  ╰ [2]: https://github.com/cloudflare/circl/tree/v1.6.1 
│                       │     ├ PublishedDate   : 2025-06-10T21:18:33Z 
│                       │     ╰ LastModifiedDate: 2025-06-10T21:18:33Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2025-48371 
│                       │     ├ PkgID           : github.com/openfga/openfga@v1.8.12 
│                       │     ├ PkgName         : github.com/openfga/openfga 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.8.12 
│                       │     │                  ╰ UID : 3d13096c276c89b0 
│                       │     ├ InstalledVersion: v1.8.12 
│                       │     ├ FixedVersion    : 1.8.13 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-48371 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : OpenFGA Authorization Bypass 
│                       │     ├ Description     : OpenFGA is an authorization/permission engine. OpenFGA
│                       │     │                   versions 1.8.0 through 1.8.12 (corresponding to Helm chart
│                       │     │                   openfga-0.2.16 through openfga-0.2.30 and docker 1.8.0
│                       │     │                   through 1.8.12) are vulnerable to authorization bypass when
│                       │     │                   certain Check and ListObject calls are executed. Users are
│                       │     │                   affected under four specific conditions: First, calling Check
│                       │     │                    API or ListObjects with an authorization model that has a
│                       │     │                   relationship directly assignable by both type bound public
│                       │     │                   access and userset; second, there are check or list object
│                       │     │                   queries with contextual tuples for the relationship that can
│                       │     │                   be directly assignable by both type bound public access and
│                       │     │                   userset; third, those contextual tuples’s user field is an
│                       │     │                   userset; and finally, type bound public access tuples are not
│                       │     │                    assigned to the relationship. Users should upgrade to
│                       │     │                   version 1.8.13 to receive a patch. The upgrade is backwards
│                       │     │                   compatible. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-285 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │     │                  ├ [1]: https://github.com/openfga/openfga/commit/e5960d4eba92b
│                       │     │                  │      723de8ff3a5346a07f50c1379ca 
│                       │     │                  ├ [2]: https://github.com/openfga/openfga/security/advisories/
│                       │     │                  │      GHSA-c72g-53hw-82q7 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2025-48371 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2025-3707 
│                       │     ├ PublishedDate   : 2025-05-22T23:15:19.23Z 
│                       │     ╰ LastModifiedDate: 2025-05-23T15:54:42.643Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2025-4673 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : 51a6e3310bee5d5c 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross- ... 
│                       │     ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross-origin redirects potentially leaking sensitive
│                       │     │                   information. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ubuntu: 2 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/679257 
│                       │     │                  ├ [1]: https://go.dev/issue/73816 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [3]: https://pkg.go.dev/vuln/GO-2025-3751 
│                       │     │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
│                       │     ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2025-0913 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : 51a6e3310bee5d5c 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
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
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/672396 
│                       │     │                  ├ [1]: https://go.dev/issue/73702 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3750 
│                       │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ╰ [4] ╭ VulnerabilityID : CVE-2025-22874 
│                             ├ PkgID           : stdlib@v1.24.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                             │                  ╰ UID : 51a6e3310bee5d5c 
│                             ├ InstalledVersion: v1.24.3 
│                             ├ FixedVersion    : 1.23.10, 1.24.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                             │                  │         efd6ad4bae877649b2e 
│                             │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                             │                            ef2ce9c5f531ec3064f 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Title           : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsag ... 
│                             ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
│                             │                   This only affected certificate chains which contain policy
│                             │                   graphs, which are rather uncommon. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/670375 
│                             │                  ├ [1]: https://go.dev/issue/73612 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3749 
│                             ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
│                             ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
├ [7] ╭ Target         : usr/share/grafana/bin/grafana-cli 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-4673 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : 8115bbbfba1b4e5d 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Title           : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross- ... 
│                       │     ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
│                       │     │                   on cross-origin redirects potentially leaking sensitive
│                       │     │                   information. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ubuntu: 2 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/679257 
│                       │     │                  ├ [1]: https://go.dev/issue/73816 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ├ [3]: https://pkg.go.dev/vuln/GO-2025-3751 
│                       │     │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
│                       │     ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2025-0913 
│                       │     ├ PkgID           : stdlib@v1.24.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                       │     │                  ╰ UID : 8115bbbfba1b4e5d 
│                       │     ├ InstalledVersion: v1.24.3 
│                       │     ├ FixedVersion    : 1.23.10, 1.24.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                       │     │                  │         efd6ad4bae877649b2e 
│                       │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                       │     │                            ef2ce9c5f531ec3064f 
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
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/672396 
│                       │     │                  ├ [1]: https://go.dev/issue/73702 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3750 
│                       │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
│                       │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2025-22874 
│                             ├ PkgID           : stdlib@v1.24.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
│                             │                  ╰ UID : 8115bbbfba1b4e5d 
│                             ├ InstalledVersion: v1.24.3 
│                             ├ FixedVersion    : 1.23.10, 1.24.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
│                             │                  │         efd6ad4bae877649b2e 
│                             │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
│                             │                            ef2ce9c5f531ec3064f 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Title           : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsag ... 
│                             ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
│                             │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
│                             │                   This only affected certificate chains which contain policy
│                             │                   graphs, which are rather uncommon. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/670375 
│                             │                  ├ [1]: https://go.dev/issue/73612 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3749 
│                             ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
│                             ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
╰ [8] ╭ Target         : usr/share/grafana/bin/grafana-server 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-4673 
                        │     ├ PkgID           : stdlib@v1.24.3 
                        │     ├ PkgName         : stdlib 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
                        │     │                  ╰ UID : 54cec8ce05afa237 
                        │     ├ InstalledVersion: v1.24.3 
                        │     ├ FixedVersion    : 1.23.10, 1.24.4 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
                        │     │                  │         efd6ad4bae877649b2e 
                        │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
                        │     │                            ef2ce9c5f531ec3064f 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-4673 
                        │     ├ DataSource       ╭ ID  : govulndb 
                        │     │                  ├ Name: The Go Vulnerability Database 
                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │     ├ Title           : Proxy-Authorization and Proxy-Authenticate headers persisted
                        │     │                   on cross- ... 
                        │     ├ Description     : Proxy-Authorization and Proxy-Authenticate headers persisted
                        │     │                   on cross-origin redirects potentially leaking sensitive
                        │     │                   information. 
                        │     ├ Severity        : MEDIUM 
                        │     ├ VendorSeverity   ─ ubuntu: 2 
                        │     ├ References       ╭ [0]: https://go.dev/cl/679257 
                        │     │                  ├ [1]: https://go.dev/issue/73816 
                        │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
                        │     │                  ├ [3]: https://pkg.go.dev/vuln/GO-2025-3751 
                        │     │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2025-4673 
                        │     ├ PublishedDate   : 2025-06-11T17:15:42.993Z 
                        │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
                        ├ [1] ╭ VulnerabilityID : CVE-2025-0913 
                        │     ├ PkgID           : stdlib@v1.24.3 
                        │     ├ PkgName         : stdlib 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
                        │     │                  ╰ UID : 54cec8ce05afa237 
                        │     ├ InstalledVersion: v1.24.3 
                        │     ├ FixedVersion    : 1.23.10, 1.24.4 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
                        │     │                  │         efd6ad4bae877649b2e 
                        │     │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
                        │     │                            ef2ce9c5f531ec3064f 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-0913 
                        │     ├ DataSource       ╭ ID  : govulndb 
                        │     │                  ├ Name: The Go Vulnerability Database 
                        │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │     ├ Title           : Inconsistent handling of O_CREATE|O_EXCL on Unix and Windows
                        │     │                   in os in syscall 
                        │     ├ Description     : os.OpenFile(path, os.O_CREATE|O_EXCL) behaved differently on
                        │     │                   Unix and Windows systems when the target path was a dangling
                        │     │                   symlink. On Unix systems, OpenFile with O_CREATE and O_EXCL
                        │     │                   flags never follows symlinks. On Windows, when the target
                        │     │                   path was a symlink to a nonexistent location, OpenFile would
                        │     │                   create a file in that location. OpenFile now always returns
                        │     │                   an error when the O_CREATE and O_EXCL flags are both set and
                        │     │                   the target path is a symlink. 
                        │     ├ Severity        : UNKNOWN 
                        │     ├ References       ╭ [0]: https://go.dev/cl/672396 
                        │     │                  ├ [1]: https://go.dev/issue/73702 
                        │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
                        │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3750 
                        │     ├ PublishedDate   : 2025-06-11T18:15:24.627Z 
                        │     ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
                        ╰ [2] ╭ VulnerabilityID : CVE-2025-22874 
                              ├ PkgID           : stdlib@v1.24.3 
                              ├ PkgName         : stdlib 
                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.24.3 
                              │                  ╰ UID : 54cec8ce05afa237 
                              ├ InstalledVersion: v1.24.3 
                              ├ FixedVersion    : 1.23.10, 1.24.4 
                              ├ Status          : fixed 
                              ├ Layer            ╭ Digest: sha256:680c031aab1bea39a8286396324874f2ad7955d6a0d84
                              │                  │         efd6ad4bae877649b2e 
                              │                  ╰ DiffID: sha256:d6914bfc24ce2205e5a1a846377d9ff87e4d3fc749919
                              │                            ef2ce9c5f531ec3064f 
                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22874 
                              ├ DataSource       ╭ ID  : govulndb 
                              │                  ├ Name: The Go Vulnerability Database 
                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
                              ├ Title           : Calling Verify with a VerifyOptions.KeyUsages that contains
                              │                   ExtKeyUsag ... 
                              ├ Description     : Calling Verify with a VerifyOptions.KeyUsages that contains
                              │                   ExtKeyUsageAny unintentionally disabledpolicy validation.
                              │                   This only affected certificate chains which contain policy
                              │                   graphs, which are rather uncommon. 
                              ├ Severity        : UNKNOWN 
                              ├ References       ╭ [0]: https://go.dev/cl/670375 
                              │                  ├ [1]: https://go.dev/issue/73612 
                              │                  ├ [2]: https://groups.google.com/g/golang-announce/c/ufZ8WpEsA3A 
                              │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3749 
                              ├ PublishedDate   : 2025-06-11T17:15:42.167Z 
                              ╰ LastModifiedDate: 2025-06-12T16:06:20.18Z 
````

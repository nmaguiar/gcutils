```yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.25.0_alpha20260805) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target         : Java 
│     ├ Class          : lang-pkgs 
│     ├ Type           : jar 
│     ├ Packages        
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2026-49844 
│                             ├ VendorIDs        ─ [0]: GHSA-qv9r-c865-cp47 
│                             ├ PkgName         : org.apache.logging.log4j:log4j-api 
│                             ├ PkgPath         : openaf/plugin-XLS/log4j-api-2.26.0.jar 
│                             ├ PkgIdentifier    ╭ PURL: pkg:maven/org.apache.logging.log4j/log4j-api@2.26.0 
│                             │                  ╰ UID : 3f0e0cb39ca9de7c 
│                             ├ InstalledVersion: 2.26.0 
│                             ├ FixedVersion    : 2.25.5, 2.26.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                             │                  │         d4b6e528ef06426e7e6 
│                             │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                             │                            1a9c14fa546310a9eba 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-49844 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:cac0cbdbd1b673e68ac3a2cd96864c542dc9248204acedeeb11000
│                             │                   ea228253a5 
│                             ├ Title           : org.apache.logging.log4j/log4j-api: Apache Log4j API:
│                             │                   Malformed JSON output due to improper encoding of
│                             │                   floating-point values 
│                             ├ Description     : Improper encoding of non-finite floating-point values during
│                             │                   MapMessage JSON serialization in Apache Log4j API produces
│                             │                   output that is not valid JSON. This issue affects Apache
│                             │                   Log4j API versions 2.13.1 through 2.25.4 and version 2.26.0.
│                             │                   
│                             │                   The fix for CVE-2026-34481 did not cover all code paths: when
│                             │                    a MapMessage contains a non-finite IEEE 754 value (NaN,
│                             │                   Infinity, or -Infinity), MapMessage.asJson() emits the
│                             │                   corresponding bare token. RFC 8259 does not permit these
│                             │                   tokens, so a conformant parser rejects the resulting
│                             │                   document.
│                             │                   The defect is reachable only when both of the following
│                             │                   conditions hold:
│                             │                     *  The application uses the  message resolver
│                             │                   https://logging.apache.org/log4j/2.x/manual/json-template-lay
│                             │                   out.html#event-template-resolver-message  of
│                             │                   JsonTemplateLayout or any other layout that relies on
│                             │                   MapMessage.asJson() or MapMessage.getFormattedMessage(new
│                             │                   String[]{"JSON"}).
│                             │                     *  The application logs a MapMessage that contains an
│                             │                   attacker-controlled floating-point value.
│                             │                   An attacker who can supply a non-finite value can cause the
│                             │                   affected layout to emit malformed JSON, which may corrupt the
│                             │                    enclosing log record or disrupt downstream log ingestion and
│                             │                    parsing.
│                             │                   Users are advised to upgrade to Apache Log4j API 2.25.5 or
│                             │                   2.26.1, both of which emit RFC 8259-compliant JSON for
│                             │                   non-finite values. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-116 
│                             ├ VendorSeverity   ╭ ghsa  : 2 
│                             │                  ├ nvd   : 2 
│                             │                  ╰ redhat: 2 
│                             ├ CVSS             ╭ ghsa   ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/V
│                             │                  │        │            I:N/VA:N/SC:N/SI:L/SA:N 
│                             │                  │        ╰ V40Score : 6.3 
│                             │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/
│                             │                  │        │           A:N 
│                             │                  │        ╰ V3Score : 5.9 
│                             │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/
│                             │                           │           A:N 
│                             │                           ╰ V3Score : 5.9 
│                             ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-49844 
│                             │                  ├ [1] : https://github.com/apache/logging-log4j2 
│                             │                  ├ [2] : https://github.com/apache/logging-log4j2/commit/19edb2
│                             │                  │       3e162d6c728a8c2221a240037d389ed300 
│                             │                  ├ [3] : https://github.com/apache/logging-log4j2/commit/feadf8
│                             │                  │       eb0b4acb6ddfa4c0ab2bbc6d88b8e12d82 
│                             │                  ├ [4] : https://github.com/apache/logging-log4j2/pull/4163 
│                             │                  ├ [5] : https://github.com/apache/logging-log4j2/releases/tag/
│                             │                  │       rel/2.25.5 
│                             │                  ├ [6] : https://github.com/apache/logging-log4j2/releases/tag/
│                             │                  │       rel/2.26.1 
│                             │                  ├ [7] : https://logging.apache.org/cyclonedx/vdr.xml 
│                             │                  ├ [8] : https://logging.apache.org/log4j/2.x/manual/json-templ
│                             │                  │       ate-layout.html#event-template-resolver-message 
│                             │                  ├ [9] : https://logging.apache.org/security.html#CVE-2026-49844 
│                             │                  ├ [10]: https://nvd.nist.gov/vuln/detail/CVE-2026-49844 
│                             │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-49844 
│                             ├ PublishedDate   : 2026-07-10T22:16:42.54Z 
│                             ╰ LastModifiedDate: 2026-07-14T20:03:09.91Z 
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
│                       │     ├ PkgID           : golang.org/x/crypto@v0.53.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.53.0 
│                       │     │                  ╰ UID : 28dd7c39c48a1330 
│                       │     ├ InstalledVersion: v0.53.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:86d7b642e7189183ba7e6bf36a2a2f8260c37be3584f9388070a61
│                       │     │                   2e3f80ac13 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-33818 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:2ff3a974168053a6199696057c629c153b25c2fc643cd29504b2ca
│                       │     │                   b80dd0ccbc 
│                       │     ├ Title           : encoding/asn1: golang: Go encoding/asn1: Denial of Service
│                       │     │                   via excessive recursion in Unmarshal 
│                       │     ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │     │                   exhaustion when parsing deeply-nested, recursive
│                       │     │                   structures. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-400 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33818 
│                       │     │                  ├ [1]: https://go.dev/cl/814980 
│                       │     │                  ├ [2]: https://go.dev/issue/80405 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33818 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33818 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:55.317Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-39821 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6f1092abfdfb3576573858b45727861c11eaa9b4b63946fe07cc03
│                       │     │                   d18194e4f5 
│                       │     ├ Title           : golang.org/x/net/idna: golang: net/http:
│                       │     │                   golang.org/x/net/idna: Privilege escalation via incorrect
│                       │     │                   Punycode label processing 
│                       │     ├ Description     : The ToASCII and ToUnicode functions incorrectly accept
│                       │     │                   Punycode-encoded labels that decode to an ASCII-only label.
│                       │     │                   For example, ToUnicode("xn--example-.com") incorrectly
│                       │     │                   returns the name "example.com" rather than an error. This
│                       │     │                   behavior can lead to privilege escalation in programs using
│                       │     │                   the idna package. For example, a program which performs
│                       │     │                   privilege checks on the ASCII hostname may reject
│                       │     │                   "example.com" but permit "xn--example-.com". If that program
│                       │     │                   subsequently converts the ASCII hostname to Unicode, it will
│                       │     │                   inadvertently permits access to the Unicode name
│                       │     │                   "example.com". 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-1289 
│                       │     ├ VendorSeverity   ╭ alma       : 3 
│                       │     │                  ├ amazon     : 3 
│                       │     │                  ├ azure      : 4 
│                       │     │                  ├ oracle-oval: 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ├ rocky      : 3 
│                       │     │                  ╰ ubuntu     : 2 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 8.2 
│                       │     ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │     │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │     │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:26546 
│                       │     │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:26547 
│                       │     │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:30650 
│                       │     │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:30651 
│                       │     │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:30853 
│                       │     │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:30854 
│                       │     │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:30855 
│                       │     │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:33155 
│                       │     │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:33160 
│                       │     │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:33163 
│                       │     │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:33173 
│                       │     │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:33183 
│                       │     │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:33524 
│                       │     │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:33531 
│                       │     │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:34342 
│                       │     │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:34364 
│                       │     │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:34789 
│                       │     │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:35826 
│                       │     │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:35827 
│                       │     │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:35828 
│                       │     │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:35829 
│                       │     │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:35830 
│                       │     │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:35831 
│                       │     │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:35993 
│                       │     │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:35994 
│                       │     │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:36105 
│                       │     │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:36167 
│                       │     │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:36207 
│                       │     │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │     │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:36651 
│                       │     │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:36796 
│                       │     │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │     │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:36808 
│                       │     │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:36820 
│                       │     │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:36883 
│                       │     │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:37387 
│                       │     │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:37435 
│                       │     │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:37436 
│                       │     │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:38995 
│                       │     │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:39005 
│                       │     │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:39573 
│                       │     │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:39879 
│                       │     │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:40118 
│                       │     │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:40262 
│                       │     │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:40945 
│                       │     │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:41019 
│                       │     │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:41030 
│                       │     │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:41031 
│                       │     │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:41036 
│                       │     │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:41055 
│                       │     │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:41066 
│                       │     │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:41928 
│                       │     │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:41930 
│                       │     │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:42043 
│                       │     │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:42047 
│                       │     │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:42048 
│                       │     │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:42049 
│                       │     │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:42050 
│                       │     │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:42051 
│                       │     │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:42078 
│                       │     │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:42079 
│                       │     │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:42080 
│                       │     │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:42082 
│                       │     │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:42132 
│                       │     │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:42142 
│                       │     │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:42146 
│                       │     │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:42150 
│                       │     │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:42151 
│                       │     │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:42240 
│                       │     │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:42644 
│                       │     │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:42796 
│                       │     │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:42852 
│                       │     │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:43038 
│                       │     │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:43052 
│                       │     │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:43692 
│                       │     │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:44622 
│                       │     │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:44624 
│                       │     │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:46395 
│                       │     │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:47149 
│                       │     │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:47735 
│                       │     │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:47737 
│                       │     │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:47952 
│                       │     │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:50300 
│                       │     │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:50843 
│                       │     │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:51033 
│                       │     │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:51112 
│                       │     │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:51187 
│                       │     │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:51194 
│                       │     │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:51341 
│                       │     │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:52826 
│                       │     │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:53374 
│                       │     │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:53412 
│                       │     │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:53413 
│                       │     │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:53415 
│                       │     │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:53530 
│                       │     │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:54191 
│                       │     │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:54274 
│                       │     │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:54283 
│                       │     │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:54284 
│                       │     │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:54285 
│                       │     │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:54286 
│                       │     │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:54287 
│                       │     │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:54395 
│                       │     │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:54401 
│                       │     │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:54435 
│                       │     │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:54441 
│                       │     │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:54531 
│                       │     │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:54580 
│                       │     │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:54757 
│                       │     │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:56143 
│                       │     │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:56223 
│                       │     │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:56340 
│                       │     │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:56431 
│                       │     │                  ├ [117]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │     │                  ├ [118]: https://bugzilla.redhat.com/2480756 
│                       │     │                  ├ [119]: https://bugzilla.redhat.com/2484207 
│                       │     │                  ├ [120]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │     │                  ├ [121]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │     │                  ├ [122]: https://creativecommons.org/licenses/by/4.0/ 
│                       │     │                  ├ [123]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39821 
│                       │     │                  ├ [124]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39822 
│                       │     │                  ├ [125]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
│                       │     │                  ├ [126]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │     │                  ├ [127]: https://github.com/golang/go/issues/78760 
│                       │     │                  ├ [128]: https://go.dev/cl/767220 
│                       │     │                  ├ [129]: https://go.dev/issue/78760 
│                       │     │                  ├ [130]: https://groups.google.com/g/golang-announce/c/94pEorn
│                       │     │                  │        pRlI 
│                       │     │                  ├ [131]: https://groups.google.com/g/golang-announce/c/iI-mYSI
│                       │     │                  │        0lu8 
│                       │     │                  ├ [132]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │     │                  ├ [133]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │     │                  ├ [134]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │     │                  ├ [135]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │     │                  ├ [136]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │     │                  │        026/cve-2026-39821.json 
│                       │     │                  ├ [137]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │     │                  ╰ [138]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │     ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │     ╰ LastModifiedDate: 2026-08-19T12:18:01.253Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:f63ae7c8c73b5eb7b345628b31e57ee40e42b6b884bd9d982e4903
│                       │     │                   9e209d2d1b 
│                       │     ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │     │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │     │                   invalid DNS record parsing 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │     │                  ├ [1]: https://go.dev/cl/786345 
│                       │     │                  ├ [2]: https://go.dev/issue/79795 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:55.673Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-56853 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:cc5e2ad65271f0398a5de1013305e57ddae3e30975b925fe2469b8
│                       │     │                   a23d020c34 
│                       │     ├ Title           : net/http: golang: Go net/http: Unencrypted HTTP/2 connections
│                       │     │                    vulnerable to Denial of Service 
│                       │     ├ Description     : When a server is configured to support unencrypted HTTP/2, it
│                       │     │                    reads a few bytes from each new connection to see if they
│                       │     │                   contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │     │                   unexpectedly not being applied when doing this. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-770 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56853 
│                       │     │                  ├ [1]: https://go.dev/cl/795540 
│                       │     │                  ├ [2]: https://go.dev/issue/80205 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56853 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56853 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:57.21Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-56858 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:2b4c3a80fe033de22a95e3281c9c7c1e4058c6714d243a5e37f7b4
│                       │     │                   2037123ec7 
│                       │     ├ Title           : html/template: golang: Go html/template: Cross-Site Scripting
│                       │     │                    via pathological input 
│                       │     ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │     │                   early, allowing for attack-controlled data to inject
│                       │     │                   arbitrary content, potentially leading to XSS. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-79 
│                       │     ├ VendorSeverity   ╭ bitnami: 2 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │     │                  │         │           /A:N 
│                       │     │                  │         ╰ V3Score : 6.1 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 8.1 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56858 
│                       │     │                  ├ [1]: https://go.dev/cl/807100 
│                       │     │                  ├ [2]: https://go.dev/issue/80435 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56858 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56858 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:57.367Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-56859 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:211f1158daa68acf2f7521f76c6975e96eda120bd19dba8367c0ea
│                       │     │                   251299ae45 
│                       │     ├ Title           : encoding/xml: golang: Go: Denial of Service via XML decoding
│                       │     │                   recursion depth issue 
│                       │     ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │     │                   causing it to never fire; this could lead to stack
│                       │     │                   exhaustion. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-770 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56859 
│                       │     │                  ├ [1]: https://go.dev/cl/803320 
│                       │     │                  ├ [2]: https://go.dev/issue/80481 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56859 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56859 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:57.523Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56860 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:23906f10dbeea9d769734ec7b138c11a937f88bdb495ec7a7ff86d
│                       │     │                   18afc76af8 
│                       │     ├ Title           : net/url: golang: golang net/url: Denial of Service from
│                       │     │                   quadratic complexity in path resolution 
│                       │     ├ Description     : Previously, resolving relative paths containing parent
│                       │     │                   directory ('..') segments performed string conversions and
│                       │     │                   buffer rewrites on each step, resulting in quadratic time
│                       │     │                   complexity and high memory allocation overhead. Now, path
│                       │     │                   resolution operates on a byte buffer using index-based
│                       │     │                   backtracking for '..' segments, eliminating the quadratic
│                       │     │                   time complexity and significantly reducing memory
│                       │     │                   allocations. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ╭ bitnami: 2 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 5.9 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56860 
│                       │     │                  ├ [1]: https://go.dev/cl/803681 
│                       │     │                  ├ [2]: https://go.dev/issue/80494 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56860 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56860 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T17:19:13.91Z 
│                       ╰ [8] ╭ VulnerabilityID : CVE-2026-56862 
│                             ├ VendorIDs        ─ [0]: GO-2026-6090 
│                             ├ PkgID           : stdlib@v1.26.5 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                             │                  ╰ UID : 8ff0a998c454a030 
│                             ├ InstalledVersion: v1.26.5 
│                             ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                             │                  │         d4b6e528ef06426e7e6 
│                             │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                             │                            1a9c14fa546310a9eba 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:289445802579b8f0d5fad4c2bbfc214a197ced90dc84dac8fa09eb
│                             │                   43e37b8247 
│                             ├ Title           : crypto/tls: golang: Golang crypto/tls: Denial of Service via
│                             │                   indefinite KeyUpdate messages 
│                             ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                             │                   as state-advancing, regardless of whether a handshake has
│                             │                   been completed or not. As a result, a malicious client can
│                             │                   keep sending KeyUpdate messages to force the server to keep
│                             │                   performing key derivation operations indefinitely. 
│                             ├ Severity        : HIGH 
│                             ├ CweIDs           ─ [0]: CWE-770 
│                             ├ VendorSeverity   ╭ bitnami: 3 
│                             │                  ╰ redhat : 3 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                             │                  │         │           /A:H 
│                             │                  │         ╰ V3Score : 7.5 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                             │                            │           /A:H 
│                             │                            ╰ V3Score : 7.5 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56862 
│                             │                  ├ [1]: https://go.dev/cl/804261 
│                             │                  ├ [2]: https://go.dev/issue/80528 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56862 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6090 
│                             │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56862 
│                             ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                             ╰ LastModifiedDate: 2026-08-14T16:16:57.717Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : GO-2026-5932 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.53.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.53.0 
│                       │     │                  ╰ UID : 855faedd270f0a78 
│                       │     ├ InstalledVersion: v0.53.0 
│                       │     ├ Status          : affected 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:3d619be46cb7fb74c5750dc7264c1bb931d2577ed17a9d53f2822b
│                       │     │                   11e8de0412 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-33818 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:58526f55f010de328ff38a2acfac5fad03b79ffdc512b8358c9d22
│                       │     │                   059eb86c31 
│                       │     ├ Title           : encoding/asn1: golang: Go encoding/asn1: Denial of Service
│                       │     │                   via excessive recursion in Unmarshal 
│                       │     ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │     │                   exhaustion when parsing deeply-nested, recursive
│                       │     │                   structures. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-400 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33818 
│                       │     │                  ├ [1]: https://go.dev/cl/814980 
│                       │     │                  ├ [2]: https://go.dev/issue/80405 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33818 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33818 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:55.317Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-39821 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:4f5b99154dd637829b594662fc58ed6c619ea0c81d81b648d2e562
│                       │     │                   ba68194ed6 
│                       │     ├ Title           : golang.org/x/net/idna: golang: net/http:
│                       │     │                   golang.org/x/net/idna: Privilege escalation via incorrect
│                       │     │                   Punycode label processing 
│                       │     ├ Description     : The ToASCII and ToUnicode functions incorrectly accept
│                       │     │                   Punycode-encoded labels that decode to an ASCII-only label.
│                       │     │                   For example, ToUnicode("xn--example-.com") incorrectly
│                       │     │                   returns the name "example.com" rather than an error. This
│                       │     │                   behavior can lead to privilege escalation in programs using
│                       │     │                   the idna package. For example, a program which performs
│                       │     │                   privilege checks on the ASCII hostname may reject
│                       │     │                   "example.com" but permit "xn--example-.com". If that program
│                       │     │                   subsequently converts the ASCII hostname to Unicode, it will
│                       │     │                   inadvertently permits access to the Unicode name
│                       │     │                   "example.com". 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-1289 
│                       │     ├ VendorSeverity   ╭ alma       : 3 
│                       │     │                  ├ amazon     : 3 
│                       │     │                  ├ azure      : 4 
│                       │     │                  ├ oracle-oval: 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ├ rocky      : 3 
│                       │     │                  ╰ ubuntu     : 2 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 8.2 
│                       │     ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │     │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │     │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:26546 
│                       │     │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:26547 
│                       │     │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:30650 
│                       │     │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:30651 
│                       │     │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:30853 
│                       │     │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:30854 
│                       │     │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:30855 
│                       │     │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:33155 
│                       │     │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:33160 
│                       │     │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:33163 
│                       │     │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:33173 
│                       │     │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:33183 
│                       │     │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:33524 
│                       │     │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:33531 
│                       │     │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:34342 
│                       │     │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:34364 
│                       │     │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:34789 
│                       │     │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:35826 
│                       │     │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:35827 
│                       │     │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:35828 
│                       │     │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:35829 
│                       │     │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:35830 
│                       │     │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:35831 
│                       │     │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:35993 
│                       │     │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:35994 
│                       │     │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:36105 
│                       │     │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:36167 
│                       │     │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:36207 
│                       │     │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │     │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:36651 
│                       │     │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:36796 
│                       │     │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │     │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:36808 
│                       │     │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:36820 
│                       │     │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:36883 
│                       │     │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:37387 
│                       │     │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:37435 
│                       │     │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:37436 
│                       │     │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:38995 
│                       │     │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:39005 
│                       │     │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:39573 
│                       │     │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:39879 
│                       │     │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:40118 
│                       │     │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:40262 
│                       │     │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:40945 
│                       │     │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:41019 
│                       │     │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:41030 
│                       │     │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:41031 
│                       │     │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:41036 
│                       │     │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:41055 
│                       │     │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:41066 
│                       │     │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:41928 
│                       │     │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:41930 
│                       │     │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:42043 
│                       │     │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:42047 
│                       │     │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:42048 
│                       │     │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:42049 
│                       │     │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:42050 
│                       │     │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:42051 
│                       │     │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:42078 
│                       │     │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:42079 
│                       │     │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:42080 
│                       │     │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:42082 
│                       │     │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:42132 
│                       │     │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:42142 
│                       │     │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:42146 
│                       │     │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:42150 
│                       │     │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:42151 
│                       │     │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:42240 
│                       │     │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:42644 
│                       │     │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:42796 
│                       │     │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:42852 
│                       │     │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:43038 
│                       │     │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:43052 
│                       │     │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:43692 
│                       │     │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:44622 
│                       │     │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:44624 
│                       │     │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:46395 
│                       │     │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:47149 
│                       │     │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:47735 
│                       │     │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:47737 
│                       │     │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:47952 
│                       │     │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:50300 
│                       │     │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:50843 
│                       │     │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:51033 
│                       │     │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:51112 
│                       │     │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:51187 
│                       │     │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:51194 
│                       │     │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:51341 
│                       │     │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:52826 
│                       │     │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:53374 
│                       │     │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:53412 
│                       │     │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:53413 
│                       │     │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:53415 
│                       │     │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:53530 
│                       │     │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:54191 
│                       │     │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:54274 
│                       │     │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:54283 
│                       │     │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:54284 
│                       │     │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:54285 
│                       │     │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:54286 
│                       │     │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:54287 
│                       │     │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:54395 
│                       │     │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:54401 
│                       │     │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:54435 
│                       │     │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:54441 
│                       │     │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:54531 
│                       │     │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:54580 
│                       │     │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:54757 
│                       │     │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:56143 
│                       │     │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:56223 
│                       │     │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:56340 
│                       │     │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:56431 
│                       │     │                  ├ [117]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │     │                  ├ [118]: https://bugzilla.redhat.com/2480756 
│                       │     │                  ├ [119]: https://bugzilla.redhat.com/2484207 
│                       │     │                  ├ [120]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │     │                  ├ [121]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │     │                  ├ [122]: https://creativecommons.org/licenses/by/4.0/ 
│                       │     │                  ├ [123]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39821 
│                       │     │                  ├ [124]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39822 
│                       │     │                  ├ [125]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
│                       │     │                  ├ [126]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │     │                  ├ [127]: https://github.com/golang/go/issues/78760 
│                       │     │                  ├ [128]: https://go.dev/cl/767220 
│                       │     │                  ├ [129]: https://go.dev/issue/78760 
│                       │     │                  ├ [130]: https://groups.google.com/g/golang-announce/c/94pEorn
│                       │     │                  │        pRlI 
│                       │     │                  ├ [131]: https://groups.google.com/g/golang-announce/c/iI-mYSI
│                       │     │                  │        0lu8 
│                       │     │                  ├ [132]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │     │                  ├ [133]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │     │                  ├ [134]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │     │                  ├ [135]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │     │                  ├ [136]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │     │                  │        026/cve-2026-39821.json 
│                       │     │                  ├ [137]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │     │                  ╰ [138]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │     ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │     ╰ LastModifiedDate: 2026-08-19T12:18:01.253Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:db6b7510e85214d99386b0c2c94bda0d75157c589e40858a3dafb1
│                       │     │                   2e2f315a63 
│                       │     ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │     │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │     │                   invalid DNS record parsing 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │     │                  ├ [1]: https://go.dev/cl/786345 
│                       │     │                  ├ [2]: https://go.dev/issue/79795 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:55.673Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-56853 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:267865f42d3e4e5e1d96d145c41017c5874b60b7fbdf8b3aafc13f
│                       │     │                   e3529f24ac 
│                       │     ├ Title           : net/http: golang: Go net/http: Unencrypted HTTP/2 connections
│                       │     │                    vulnerable to Denial of Service 
│                       │     ├ Description     : When a server is configured to support unencrypted HTTP/2, it
│                       │     │                    reads a few bytes from each new connection to see if they
│                       │     │                   contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │     │                   unexpectedly not being applied when doing this. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-770 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56853 
│                       │     │                  ├ [1]: https://go.dev/cl/795540 
│                       │     │                  ├ [2]: https://go.dev/issue/80205 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56853 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56853 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:57.21Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-56858 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:eda0d347bf0e231247bd5aacedc6a0aed7a847c37c8d122cd90515
│                       │     │                   0ddd1385ba 
│                       │     ├ Title           : html/template: golang: Go html/template: Cross-Site Scripting
│                       │     │                    via pathological input 
│                       │     ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │     │                   early, allowing for attack-controlled data to inject
│                       │     │                   arbitrary content, potentially leading to XSS. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-79 
│                       │     ├ VendorSeverity   ╭ bitnami: 2 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │     │                  │         │           /A:N 
│                       │     │                  │         ╰ V3Score : 6.1 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 8.1 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56858 
│                       │     │                  ├ [1]: https://go.dev/cl/807100 
│                       │     │                  ├ [2]: https://go.dev/issue/80435 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56858 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56858 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:57.367Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-56859 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:f7d87103a23bec40bb15673501a035633c9c92781d5f7809c1eff4
│                       │     │                   ac74979119 
│                       │     ├ Title           : encoding/xml: golang: Go: Denial of Service via XML decoding
│                       │     │                   recursion depth issue 
│                       │     ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │     │                   causing it to never fire; this could lead to stack
│                       │     │                   exhaustion. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-770 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56859 
│                       │     │                  ├ [1]: https://go.dev/cl/803320 
│                       │     │                  ├ [2]: https://go.dev/issue/80481 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56859 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56859 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T16:16:57.523Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56860 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                       │     │                  │         d4b6e528ef06426e7e6 
│                       │     │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                       │     │                            1a9c14fa546310a9eba 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:20c9dedf4478bbb373a9b6ae6dc942a1c00a0183854307aa8f506a
│                       │     │                   ee356432a8 
│                       │     ├ Title           : net/url: golang: golang net/url: Denial of Service from
│                       │     │                   quadratic complexity in path resolution 
│                       │     ├ Description     : Previously, resolving relative paths containing parent
│                       │     │                   directory ('..') segments performed string conversions and
│                       │     │                   buffer rewrites on each step, resulting in quadratic time
│                       │     │                   complexity and high memory allocation overhead. Now, path
│                       │     │                   resolution operates on a byte buffer using index-based
│                       │     │                   backtracking for '..' segments, eliminating the quadratic
│                       │     │                   time complexity and significantly reducing memory
│                       │     │                   allocations. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ╭ bitnami: 2 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 5.9 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56860 
│                       │     │                  ├ [1]: https://go.dev/cl/803681 
│                       │     │                  ├ [2]: https://go.dev/issue/80494 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56860 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56860 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │     ╰ LastModifiedDate: 2026-08-14T17:19:13.91Z 
│                       ╰ [8] ╭ VulnerabilityID : CVE-2026-56862 
│                             ├ VendorIDs        ─ [0]: GO-2026-6090 
│                             ├ PkgID           : stdlib@v1.26.5 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                             │                  ╰ UID : b28b13f09fb71390 
│                             ├ InstalledVersion: v1.26.5 
│                             ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535e
│                             │                  │         d4b6e528ef06426e7e6 
│                             │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f23
│                             │                            1a9c14fa546310a9eba 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:396515a1834fbfb04334da7179de9f40c7ee75330dbee110c23349
│                             │                   2837e44b50 
│                             ├ Title           : crypto/tls: golang: Golang crypto/tls: Denial of Service via
│                             │                   indefinite KeyUpdate messages 
│                             ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                             │                   as state-advancing, regardless of whether a handshake has
│                             │                   been completed or not. As a result, a malicious client can
│                             │                   keep sending KeyUpdate messages to force the server to keep
│                             │                   performing key derivation operations indefinitely. 
│                             ├ Severity        : HIGH 
│                             ├ CweIDs           ─ [0]: CWE-770 
│                             ├ VendorSeverity   ╭ bitnami: 3 
│                             │                  ╰ redhat : 3 
│                             ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                             │                  │         │           /A:H 
│                             │                  │         ╰ V3Score : 7.5 
│                             │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                             │                            │           /A:H 
│                             │                            ╰ V3Score : 7.5 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56862 
│                             │                  ├ [1]: https://go.dev/cl/804261 
│                             │                  ├ [2]: https://go.dev/issue/80528 
│                             │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56862 
│                             │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6090 
│                             │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56862 
│                             ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                             ╰ LastModifiedDate: 2026-08-14T16:16:57.717Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-21728 
│                       │      ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20260427
│                       │      │                  │       112133-525d1bab07e0 
│                       │      │                  ╰ UID : 18b157406ef90a65 
│                       │      ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │      ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:9b51b2d7e1ef81ba1f011ea514c681e9887634b1ce8b168b25f48
│                       │      │                   91f33239573 
│                       │      ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                       │      ├ Description     : Tempo queries with large limits can cause large memory
│                       │      │                   allocations which can impact the availability of the
│                       │      │                   service, depending on its deployment strategy.
│                       │      │                   
│                       │      │                   Mitigation can be done by setting max_result_limit in the
│                       │      │                   search config, e.g. to 262144 (2^18). Alternatively,
│                       │      │                   automatically restart the service. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-400 
│                       │      │                  ╰ [1]: CWE-770 
│                       │      ├ VendorSeverity   ╭ ghsa  : 3 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:21769 
│                       │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:22347 
│                       │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:22423 
│                       │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:23345 
│                       │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:24503 
│                       │      │                  ├ [5] : https://access.redhat.com/security/cve/CVE-2026-21728 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2461395 
│                       │      │                  ├ [7] : https://github.com/grafana/tempo 
│                       │      │                  ├ [8] : https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0
│                       │      │                  │       b67498b662b85a148698b4afd/docs/sources/tempo/release-
│                       │      │                  │       notes/version-2/v2-10.md?plain=1#L328 
│                       │      │                  ├ [9] : https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0
│                       │      │                  │       b67498b662b85a148698b4afd/docs/sources/tempo/release-
│                       │      │                  │       notes/version-2/v2-8.md?plain=1#L251 
│                       │      │                  ├ [10]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0
│                       │      │                  │       b67498b662b85a148698b4afd/docs/sources/tempo/release-
│                       │      │                  │       notes/version-2/v2-9.md?plain=1#L224 
│                       │      │                  ├ [11]: https://github.com/grafana/tempo/commit/650eb1985a077
│                       │      │                  │       6789c8564122990f588a742356f 
│                       │      │                  ├ [12]: https://github.com/grafana/tempo/pull/6525 
│                       │      │                  ├ [13]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2026-21728 
│                       │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-21728 
│                       │      │                  ├ [15]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │      │                  │       026/cve-2026-21728.json 
│                       │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-21728 
│                       │      ├ PublishedDate   : 2026-04-24T09:16:03.71Z 
│                       │      ╰ LastModifiedDate: 2026-08-17T12:17:18.15Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-28377 
│                       │      ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20260427112133-525d1bab07e0 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20260427
│                       │      │                  │       112133-525d1bab07e0 
│                       │      │                  ╰ UID : 18b157406ef90a65 
│                       │      ├ InstalledVersion: v1.5.1-0.20260427112133-525d1bab07e0 
│                       │      ├ FixedVersion    : 2.10.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:62afa896e984eaa1392fe18d2fb056528471cd1ac00305690ffb0
│                       │      │                   7f3ae30d9fb 
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
│                       │      │                  ├ [1]: https://github.com/advisories/GHSA-ffqx-q65f-36jf 
│                       │      │                  ├ [2]: https://github.com/grafana/tempo 
│                       │      │                  ├ [3]: https://github.com/grafana/tempo/blob/4dc3e5b0d3463a0b
│                       │      │                  │      67498b662b85a148698b4afd/CHANGELOG.md?plain=1#L135 
│                       │      │                  ├ [4]: https://github.com/grafana/tempo/commit/bb8ca663db34a0
│                       │      │                  │      980c9758b40d918fda3b4dbec3 
│                       │      │                  ├ [5]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      026-28377 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-28377 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-28377 
│                       │      ├ PublishedDate   : 2026-03-26T22:16:28.46Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
│                       ├ [2]  ╭ VulnerabilityID : GO-2026-5932 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.54.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.54.0 
│                       │      │                  ╰ UID : e3329ce6867cede8 
│                       │      ├ InstalledVersion: v0.54.0 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:85a511485e2ed5428be9ce0d8193ac925e2e045043e51ad4cada1
│                       │      │                   743f8381433 
│                       │      ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                       │      │                   unsafe by design, and has known security issues 
│                       │      ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                       │      │                    has numerous known security issues, is not maintained, and
│                       │      │                   should not be used.
│                       │      │                   
│                       │      │                   If you are required to interoperate with OpenPGP systems and
│                       │      │                    need a maintained package, consider
│                       │      │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                       │      │                   maintained fork that aims to be a drop-in replacement for
│                       │      │                   this package. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                       │                         ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-33818 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:27733bc5c1638551bc895a5b0859c4dab328490d4f739203f3cae
│                       │      │                   a1138d9e302 
│                       │      ├ Title           : encoding/asn1: golang: Go encoding/asn1: Denial of Service
│                       │      │                   via excessive recursion in Unmarshal 
│                       │      ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │      │                   exhaustion when parsing deeply-nested, recursive
│                       │      │                   structures. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-400 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33818 
│                       │      │                  ├ [1]: https://go.dev/cl/814980 
│                       │      │                  ├ [2]: https://go.dev/issue/80405 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33818 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33818 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:55.317Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39821 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:9e1b284d7342136884fe1c1e1d93f88ab1aab5e757b875ec0d81a
│                       │      │                   f271119e431 
│                       │      ├ Title           : golang.org/x/net/idna: golang: net/http:
│                       │      │                   golang.org/x/net/idna: Privilege escalation via incorrect
│                       │      │                   Punycode label processing 
│                       │      ├ Description     : The ToASCII and ToUnicode functions incorrectly accept
│                       │      │                   Punycode-encoded labels that decode to an ASCII-only label.
│                       │      │                   For example, ToUnicode("xn--example-.com") incorrectly
│                       │      │                   returns the name "example.com" rather than an error. This
│                       │      │                   behavior can lead to privilege escalation in programs using
│                       │      │                   the idna package. For example, a program which performs
│                       │      │                   privilege checks on the ASCII hostname may reject
│                       │      │                   "example.com" but permit "xn--example-.com". If that program
│                       │      │                    subsequently converts the ASCII hostname to Unicode, it
│                       │      │                   will inadvertently permits access to the Unicode name
│                       │      │                   "example.com". 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-1289 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 3 
│                       │      │                  ├ azure      : 4 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ├ rocky      : 3 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 8.2 
│                       │      ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │      │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │      │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:26546 
│                       │      │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:26547 
│                       │      │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:30650 
│                       │      │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:30651 
│                       │      │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:30853 
│                       │      │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:30854 
│                       │      │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:30855 
│                       │      │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:33155 
│                       │      │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:33160 
│                       │      │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:33163 
│                       │      │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:33173 
│                       │      │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:33183 
│                       │      │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:33524 
│                       │      │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:33531 
│                       │      │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:34342 
│                       │      │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │      │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │      │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:34364 
│                       │      │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:34789 
│                       │      │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:35826 
│                       │      │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:35827 
│                       │      │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:35828 
│                       │      │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:35829 
│                       │      │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:35830 
│                       │      │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:35831 
│                       │      │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:35993 
│                       │      │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:35994 
│                       │      │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:36105 
│                       │      │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:36167 
│                       │      │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:36207 
│                       │      │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │      │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:36651 
│                       │      │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:36796 
│                       │      │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │      │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:36808 
│                       │      │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:36820 
│                       │      │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:36883 
│                       │      │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:37387 
│                       │      │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:37435 
│                       │      │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:37436 
│                       │      │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:38995 
│                       │      │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:39005 
│                       │      │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:39573 
│                       │      │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:39879 
│                       │      │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:40118 
│                       │      │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:40262 
│                       │      │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:40945 
│                       │      │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:41019 
│                       │      │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:41030 
│                       │      │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:41031 
│                       │      │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:41036 
│                       │      │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:41055 
│                       │      │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:41066 
│                       │      │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:41928 
│                       │      │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:41930 
│                       │      │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:42043 
│                       │      │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:42047 
│                       │      │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:42048 
│                       │      │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:42049 
│                       │      │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:42050 
│                       │      │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:42051 
│                       │      │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:42078 
│                       │      │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:42079 
│                       │      │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:42080 
│                       │      │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:42082 
│                       │      │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:42132 
│                       │      │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:42142 
│                       │      │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:42146 
│                       │      │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:42150 
│                       │      │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:42151 
│                       │      │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:42240 
│                       │      │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:42644 
│                       │      │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:42796 
│                       │      │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:42852 
│                       │      │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:43038 
│                       │      │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:43052 
│                       │      │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:43692 
│                       │      │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:44622 
│                       │      │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:44624 
│                       │      │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:46395 
│                       │      │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:47149 
│                       │      │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:47735 
│                       │      │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:47737 
│                       │      │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:47952 
│                       │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:50300 
│                       │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:50843 
│                       │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:51033 
│                       │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:51112 
│                       │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:51187 
│                       │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:51194 
│                       │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:51341 
│                       │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:52826 
│                       │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:53374 
│                       │      │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:53412 
│                       │      │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:53413 
│                       │      │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:53415 
│                       │      │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:53530 
│                       │      │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:54191 
│                       │      │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:54274 
│                       │      │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:54283 
│                       │      │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:54284 
│                       │      │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:54285 
│                       │      │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:54286 
│                       │      │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:54287 
│                       │      │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:54395 
│                       │      │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:54401 
│                       │      │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:54435 
│                       │      │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:54441 
│                       │      │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:54531 
│                       │      │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:54580 
│                       │      │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:54757 
│                       │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:56143 
│                       │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:56223 
│                       │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:56340 
│                       │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:56431 
│                       │      │                  ├ [117]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │      │                  ├ [118]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [119]: https://bugzilla.redhat.com/2484207 
│                       │      │                  ├ [120]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │      │                  ├ [121]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │      │                  ├ [122]: https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [123]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39821 
│                       │      │                  ├ [124]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39822 
│                       │      │                  ├ [125]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
│                       │      │                  ├ [126]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │      │                  ├ [127]: https://github.com/golang/go/issues/78760 
│                       │      │                  ├ [128]: https://go.dev/cl/767220 
│                       │      │                  ├ [129]: https://go.dev/issue/78760 
│                       │      │                  ├ [130]: https://groups.google.com/g/golang-announce/c/94pEor
│                       │      │                  │        npRlI 
│                       │      │                  ├ [131]: https://groups.google.com/g/golang-announce/c/iI-mYS
│                       │      │                  │        I0lu8 
│                       │      │                  ├ [132]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │      │                  ├ [133]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │      │                  ├ [134]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │      │                  ├ [135]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │      │                  ├ [136]: https://security.access.redhat.com/data/csaf/v2/vex/
│                       │      │                  │        2026/cve-2026-39821.json 
│                       │      │                  ├ [137]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │      │                  ╰ [138]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │      ╰ LastModifiedDate: 2026-08-19T12:18:01.253Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-46600 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b92c24031a30f0006a5a11b68333c914452629888ed0e859ddad8
│                       │      │                   b8db7a3cc15 
│                       │      ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │      │                   invalid DNS record parsing 
│                       │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │      │                   of a parameter value overflows the message buffer. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-125 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │      │                  ├ [1]: https://go.dev/cl/786345 
│                       │      │                  ├ [2]: https://go.dev/issue/79795 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:55.673Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-56853 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:a4cc9c06c141d84b68348c7648c3bc6c0f6213fc41d56383777d5
│                       │      │                   ef7f8e0b583 
│                       │      ├ Title           : net/http: golang: Go net/http: Unencrypted HTTP/2
│                       │      │                   connections vulnerable to Denial of Service 
│                       │      ├ Description     : When a server is configured to support unencrypted HTTP/2,
│                       │      │                   it reads a few bytes from each new connection to see if they
│                       │      │                    contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │      │                   unexpectedly not being applied when doing this. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56853 
│                       │      │                  ├ [1]: https://go.dev/cl/795540 
│                       │      │                  ├ [2]: https://go.dev/issue/80205 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56853 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56853 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.21Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-56858 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b32ad304d9e5ec403162b6f3d47e7926c024b19bdd582fedbedcc
│                       │      │                   269eae383bd 
│                       │      ├ Title           : html/template: golang: Go html/template: Cross-Site
│                       │      │                   Scripting via pathological input 
│                       │      ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │      │                    early, allowing for attack-controlled data to inject
│                       │      │                   arbitrary content, potentially leading to XSS. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
│                       │      │                            │           H/A:N 
│                       │      │                            ╰ V3Score : 8.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56858 
│                       │      │                  ├ [1]: https://go.dev/cl/807100 
│                       │      │                  ├ [2]: https://go.dev/issue/80435 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56858 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56858 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.367Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-56859 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5be6225c5c4fa221ec1243475582842a9b39acb3d00defe4513e7
│                       │      │                   2e47e30d4d4 
│                       │      ├ Title           : encoding/xml: golang: Go: Denial of Service via XML decoding
│                       │      │                    recursion depth issue 
│                       │      ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │      │                   causing it to never fire; this could lead to stack
│                       │      │                   exhaustion. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56859 
│                       │      │                  ├ [1]: https://go.dev/cl/803320 
│                       │      │                  ├ [2]: https://go.dev/issue/80481 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56859 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56859 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.523Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-56860 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:0a33358ddaff6fa1de3cc143c100a76017b54a28bfd7fd9d4e9c6
│                       │      │                   2de8b71d30c 
│                       │      ├ Title           : net/url: golang: golang net/url: Denial of Service from
│                       │      │                   quadratic complexity in path resolution 
│                       │      ├ Description     : Previously, resolving relative paths containing parent
│                       │      │                   directory ('..') segments performed string conversions and
│                       │      │                   buffer rewrites on each step, resulting in quadratic time
│                       │      │                   complexity and high memory allocation overhead. Now, path
│                       │      │                   resolution operates on a byte buffer using index-based
│                       │      │                   backtracking for '..' segments, eliminating the quadratic
│                       │      │                   time complexity and significantly reducing memory
│                       │      │                   allocations. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 5.9 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56860 
│                       │      │                  ├ [1]: https://go.dev/cl/803681 
│                       │      │                  ├ [2]: https://go.dev/issue/80494 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56860 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56860 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T17:19:13.91Z 
│                       ╰ [10] ╭ VulnerabilityID : CVE-2026-56862 
│                              ├ VendorIDs        ─ [0]: GO-2026-6090 
│                              ├ PkgID           : stdlib@v1.26.5 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                              │                  ╰ UID : 8a8a3a8f15e1f251 
│                              ├ InstalledVersion: v1.26.5 
│                              ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                              │                  │         ed4b6e528ef06426e7e6 
│                              │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                              │                            31a9c14fa546310a9eba 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:284a82db60cf12160021db9a71c08b22d40e01e4402fae9d7449b
│                              │                   6cf469b162d 
│                              ├ Title           : crypto/tls: golang: Golang crypto/tls: Denial of Service via
│                              │                    indefinite KeyUpdate messages 
│                              ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                              │                    as state-advancing, regardless of whether a handshake has
│                              │                   been completed or not. As a result, a malicious client can
│                              │                   keep sending KeyUpdate messages to force the server to keep
│                              │                   performing key derivation operations indefinitely. 
│                              ├ Severity        : HIGH 
│                              ├ CweIDs           ─ [0]: CWE-770 
│                              ├ VendorSeverity   ╭ bitnami: 3 
│                              │                  ╰ redhat : 3 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           N/A:H 
│                              │                  │         ╰ V3Score : 7.5 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           N/A:H 
│                              │                            ╰ V3Score : 7.5 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56862 
│                              │                  ├ [1]: https://go.dev/cl/804261 
│                              │                  ├ [2]: https://go.dev/issue/80528 
│                              │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                              │                  │      RlI 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56862 
│                              │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6090 
│                              │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56862 
│                              ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                              ╰ LastModifiedDate: 2026-08-14T16:16:57.717Z 
├ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
│     │                  rce_linux_amd64 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : GO-2026-5932 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.53.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.53.0 
│                       │      │                  ╰ UID : a6428f802fb460f4 
│                       │      ├ InstalledVersion: v0.53.0 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5c2047013046e2d9310767d4552cc4b9d064a0bebc7087cca927f
│                       │      │                   e66d570ecbb 
│                       │      ├ Title           : The golang.org/x/crypto/openpgp package is unmaintained,
│                       │      │                   unsafe by design, and has known security issues 
│                       │      ├ Description     : The golang.org/x/crypto/openpgp package is unsafe by design,
│                       │      │                    has numerous known security issues, is not maintained, and
│                       │      │                   should not be used.
│                       │      │                   
│                       │      │                   If you are required to interoperate with OpenPGP systems and
│                       │      │                    need a maintained package, consider
│                       │      │                   github.com/ProtonMail/go-crypto/openpgp which is a
│                       │      │                   maintained fork that aims to be a drop-in replacement for
│                       │      │                   this package. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ╰ References       ╭ [0]: https://go.dev/issue/44226 
│                       │                         ╰ [1]: https://pkg.go.dev/vuln/GO-2026-5932 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-27145 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:61d4b216580ea88ed7652de418f1c70096c1f1b8fff9ea81e31b5
│                       │      │                   f6773fb5e99 
│                       │      ├ Title           : crypto/x509: golang: golang crypto/x509: Denial of Service
│                       │      │                   via excessive processing of DNS SAN entries 
│                       │      ├ Description     : (*x509.Certificate).VerifyHostname previously called
│                       │      │                   matchHostnames in a loop over all DNS Subject Alternative
│                       │      │                   Name (SAN) entries. This caused strings.Split(host, ".") to
│                       │      │                   execute repeatedly on the same input hostname. With a large
│                       │      │                   DNS SAN list, verification costs scaled quadratically based
│                       │      │                   on the number of SAN entries multiplied by the hostname's
│                       │      │                   label count. Because x509.Verify validates hostnames before
│                       │      │                   building the certificate chain, this overhead occurred even
│                       │      │                   for untrusted certificates. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-606 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 2 
│                       │      │                  ├ azure      : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ photon     : 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ╰ rocky      : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           L/A:H 
│                       │      │                  │         ╰ V3Score : 6.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:29980 
│                       │      │                  ├ [3] : https://access.redhat.com/errata/RHSA-2026:29981 
│                       │      │                  ├ [4] : https://access.redhat.com/errata/RHSA-2026:33574 
│                       │      │                  ├ [5] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │      │                  ├ [6] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:35832 
│                       │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:36317 
│                       │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:36797 
│                       │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:38995 
│                       │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:39005 
│                       │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:39573 
│                       │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:39879 
│                       │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:41030 
│                       │      │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:41036 
│                       │      │                  ├ [17]: https://access.redhat.com/errata/RHSA-2026:41930 
│                       │      │                  ├ [18]: https://access.redhat.com/errata/RHSA-2026:42043 
│                       │      │                  ├ [19]: https://access.redhat.com/errata/RHSA-2026:42047 
│                       │      │                  ├ [20]: https://access.redhat.com/errata/RHSA-2026:42049 
│                       │      │                  ├ [21]: https://access.redhat.com/errata/RHSA-2026:42050 
│                       │      │                  ├ [22]: https://access.redhat.com/errata/RHSA-2026:42051 
│                       │      │                  ├ [23]: https://access.redhat.com/errata/RHSA-2026:42079 
│                       │      │                  ├ [24]: https://access.redhat.com/errata/RHSA-2026:42080 
│                       │      │                  ├ [25]: https://access.redhat.com/errata/RHSA-2026:42082 
│                       │      │                  ├ [26]: https://access.redhat.com/errata/RHSA-2026:42142 
│                       │      │                  ├ [27]: https://access.redhat.com/errata/RHSA-2026:42150 
│                       │      │                  ├ [28]: https://access.redhat.com/errata/RHSA-2026:42151 
│                       │      │                  ├ [29]: https://access.redhat.com/errata/RHSA-2026:42240 
│                       │      │                  ├ [30]: https://access.redhat.com/errata/RHSA-2026:42644 
│                       │      │                  ├ [31]: https://access.redhat.com/errata/RHSA-2026:42946 
│                       │      │                  ├ [32]: https://access.redhat.com/errata/RHSA-2026:44622 
│                       │      │                  ├ [33]: https://access.redhat.com/errata/RHSA-2026:46394 
│                       │      │                  ├ [34]: https://access.redhat.com/errata/RHSA-2026:46395 
│                       │      │                  ├ [35]: https://access.redhat.com/errata/RHSA-2026:47149 
│                       │      │                  ├ [36]: https://access.redhat.com/errata/RHSA-2026:47735 
│                       │      │                  ├ [37]: https://access.redhat.com/errata/RHSA-2026:47737 
│                       │      │                  ├ [38]: https://access.redhat.com/errata/RHSA-2026:49703 
│                       │      │                  ├ [39]: https://access.redhat.com/errata/RHSA-2026:49705 
│                       │      │                  ├ [40]: https://access.redhat.com/errata/RHSA-2026:49729 
│                       │      │                  ├ [41]: https://access.redhat.com/errata/RHSA-2026:49744 
│                       │      │                  ├ [42]: https://access.redhat.com/errata/RHSA-2026:49765 
│                       │      │                  ├ [43]: https://access.redhat.com/errata/RHSA-2026:49770 
│                       │      │                  ├ [44]: https://access.redhat.com/errata/RHSA-2026:50205 
│                       │      │                  ├ [45]: https://access.redhat.com/errata/RHSA-2026:50319 
│                       │      │                  ├ [46]: https://access.redhat.com/errata/RHSA-2026:51057 
│                       │      │                  ├ [47]: https://access.redhat.com/errata/RHSA-2026:51187 
│                       │      │                  ├ [48]: https://access.redhat.com/errata/RHSA-2026:52946 
│                       │      │                  ├ [49]: https://access.redhat.com/errata/RHSA-2026:53374 
│                       │      │                  ├ [50]: https://access.redhat.com/errata/RHSA-2026:53412 
│                       │      │                  ├ [51]: https://access.redhat.com/errata/RHSA-2026:53413 
│                       │      │                  ├ [52]: https://access.redhat.com/errata/RHSA-2026:53415 
│                       │      │                  ├ [53]: https://access.redhat.com/errata/RHSA-2026:53416 
│                       │      │                  ├ [54]: https://access.redhat.com/errata/RHSA-2026:53530 
│                       │      │                  ├ [55]: https://access.redhat.com/errata/RHSA-2026:54168 
│                       │      │                  ├ [56]: https://access.redhat.com/errata/RHSA-2026:54401 
│                       │      │                  ├ [57]: https://access.redhat.com/errata/RHSA-2026:54427 
│                       │      │                  ├ [58]: https://access.redhat.com/errata/RHSA-2026:54432 
│                       │      │                  ├ [59]: https://access.redhat.com/errata/RHSA-2026:54435 
│                       │      │                  ├ [60]: https://access.redhat.com/errata/RHSA-2026:54441 
│                       │      │                  ├ [61]: https://access.redhat.com/errata/RHSA-2026:54500 
│                       │      │                  ├ [62]: https://access.redhat.com/errata/RHSA-2026:54525 
│                       │      │                  ├ [63]: https://access.redhat.com/errata/RHSA-2026:54531 
│                       │      │                  ├ [64]: https://access.redhat.com/errata/RHSA-2026:54603 
│                       │      │                  ├ [65]: https://access.redhat.com/errata/RHSA-2026:54757 
│                       │      │                  ├ [66]: https://access.redhat.com/errata/RHSA-2026:55899 
│                       │      │                  ├ [67]: https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │      │                  ├ [68]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [69]: https://bugzilla.redhat.com/2484207 
│                       │      │                  ├ [70]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │      │                  ├ [71]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │      │                  ├ [72]: https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [73]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-25679 
│                       │      │                  ├ [74]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-27145 
│                       │      │                  ├ [75]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
│                       │      │                  ├ [76]: https://errata.rockylinux.org/RLSA-2026:36317 
│                       │      │                  ├ [77]: https://go.dev/cl/783621 
│                       │      │                  ├ [78]: https://go.dev/issue/79694 
│                       │      │                  ├ [79]: https://groups.google.com/g/golang-announce/c/tKs3rmc
│                       │      │                  │       BcKw 
│                       │      │                  ├ [80]: https://linux.oracle.com/cve/CVE-2026-27145.html 
│                       │      │                  ├ [81]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │      │                  ├ [82]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │      │                  ├ [83]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      │                  ├ [84]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │      │                  │       026/cve-2026-27145.json 
│                       │      │                  ╰ [85]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-08-19T12:17:39.17Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-33818 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:9d38414cf2606998f3ada0fdf84b302ccfdf769578e55700f889a
│                       │      │                   a9f6f71458c 
│                       │      ├ Title           : encoding/asn1: golang: Go encoding/asn1: Denial of Service
│                       │      │                   via excessive recursion in Unmarshal 
│                       │      ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │      │                   exhaustion when parsing deeply-nested, recursive
│                       │      │                   structures. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-400 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33818 
│                       │      │                  ├ [1]: https://go.dev/cl/814980 
│                       │      │                  ├ [2]: https://go.dev/issue/80405 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33818 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33818 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:55.317Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-39821 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b9bf0c14e63df37e2125e56dee09de0d67d2b90c89a0c12b45e15
│                       │      │                   5285e37b811 
│                       │      ├ Title           : golang.org/x/net/idna: golang: net/http:
│                       │      │                   golang.org/x/net/idna: Privilege escalation via incorrect
│                       │      │                   Punycode label processing 
│                       │      ├ Description     : The ToASCII and ToUnicode functions incorrectly accept
│                       │      │                   Punycode-encoded labels that decode to an ASCII-only label.
│                       │      │                   For example, ToUnicode("xn--example-.com") incorrectly
│                       │      │                   returns the name "example.com" rather than an error. This
│                       │      │                   behavior can lead to privilege escalation in programs using
│                       │      │                   the idna package. For example, a program which performs
│                       │      │                   privilege checks on the ASCII hostname may reject
│                       │      │                   "example.com" but permit "xn--example-.com". If that program
│                       │      │                    subsequently converts the ASCII hostname to Unicode, it
│                       │      │                   will inadvertently permits access to the Unicode name
│                       │      │                   "example.com". 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-1289 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 3 
│                       │      │                  ├ azure      : 4 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ├ rocky      : 3 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 8.2 
│                       │      ├ References       ╭ [0]  : https://access.redhat.com/errata/RHSA-2026:23262 
│                       │      │                  ├ [1]  : https://access.redhat.com/errata/RHSA-2026:23264 
│                       │      │                  ├ [2]  : https://access.redhat.com/errata/RHSA-2026:26546 
│                       │      │                  ├ [3]  : https://access.redhat.com/errata/RHSA-2026:26547 
│                       │      │                  ├ [4]  : https://access.redhat.com/errata/RHSA-2026:30650 
│                       │      │                  ├ [5]  : https://access.redhat.com/errata/RHSA-2026:30651 
│                       │      │                  ├ [6]  : https://access.redhat.com/errata/RHSA-2026:30853 
│                       │      │                  ├ [7]  : https://access.redhat.com/errata/RHSA-2026:30854 
│                       │      │                  ├ [8]  : https://access.redhat.com/errata/RHSA-2026:30855 
│                       │      │                  ├ [9]  : https://access.redhat.com/errata/RHSA-2026:33155 
│                       │      │                  ├ [10] : https://access.redhat.com/errata/RHSA-2026:33160 
│                       │      │                  ├ [11] : https://access.redhat.com/errata/RHSA-2026:33163 
│                       │      │                  ├ [12] : https://access.redhat.com/errata/RHSA-2026:33173 
│                       │      │                  ├ [13] : https://access.redhat.com/errata/RHSA-2026:33183 
│                       │      │                  ├ [14] : https://access.redhat.com/errata/RHSA-2026:33524 
│                       │      │                  ├ [15] : https://access.redhat.com/errata/RHSA-2026:33531 
│                       │      │                  ├ [16] : https://access.redhat.com/errata/RHSA-2026:34342 
│                       │      │                  ├ [17] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │      │                  ├ [18] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │      │                  ├ [19] : https://access.redhat.com/errata/RHSA-2026:34364 
│                       │      │                  ├ [20] : https://access.redhat.com/errata/RHSA-2026:34789 
│                       │      │                  ├ [21] : https://access.redhat.com/errata/RHSA-2026:35826 
│                       │      │                  ├ [22] : https://access.redhat.com/errata/RHSA-2026:35827 
│                       │      │                  ├ [23] : https://access.redhat.com/errata/RHSA-2026:35828 
│                       │      │                  ├ [24] : https://access.redhat.com/errata/RHSA-2026:35829 
│                       │      │                  ├ [25] : https://access.redhat.com/errata/RHSA-2026:35830 
│                       │      │                  ├ [26] : https://access.redhat.com/errata/RHSA-2026:35831 
│                       │      │                  ├ [27] : https://access.redhat.com/errata/RHSA-2026:35993 
│                       │      │                  ├ [28] : https://access.redhat.com/errata/RHSA-2026:35994 
│                       │      │                  ├ [29] : https://access.redhat.com/errata/RHSA-2026:36105 
│                       │      │                  ├ [30] : https://access.redhat.com/errata/RHSA-2026:36167 
│                       │      │                  ├ [31] : https://access.redhat.com/errata/RHSA-2026:36207 
│                       │      │                  ├ [32] : https://access.redhat.com/errata/RHSA-2026:36648 
│                       │      │                  ├ [33] : https://access.redhat.com/errata/RHSA-2026:36651 
│                       │      │                  ├ [34] : https://access.redhat.com/errata/RHSA-2026:36796 
│                       │      │                  ├ [35] : https://access.redhat.com/errata/RHSA-2026:36797 
│                       │      │                  ├ [36] : https://access.redhat.com/errata/RHSA-2026:36808 
│                       │      │                  ├ [37] : https://access.redhat.com/errata/RHSA-2026:36820 
│                       │      │                  ├ [38] : https://access.redhat.com/errata/RHSA-2026:36883 
│                       │      │                  ├ [39] : https://access.redhat.com/errata/RHSA-2026:37387 
│                       │      │                  ├ [40] : https://access.redhat.com/errata/RHSA-2026:37435 
│                       │      │                  ├ [41] : https://access.redhat.com/errata/RHSA-2026:37436 
│                       │      │                  ├ [42] : https://access.redhat.com/errata/RHSA-2026:38995 
│                       │      │                  ├ [43] : https://access.redhat.com/errata/RHSA-2026:39005 
│                       │      │                  ├ [44] : https://access.redhat.com/errata/RHSA-2026:39573 
│                       │      │                  ├ [45] : https://access.redhat.com/errata/RHSA-2026:39879 
│                       │      │                  ├ [46] : https://access.redhat.com/errata/RHSA-2026:40118 
│                       │      │                  ├ [47] : https://access.redhat.com/errata/RHSA-2026:40262 
│                       │      │                  ├ [48] : https://access.redhat.com/errata/RHSA-2026:40945 
│                       │      │                  ├ [49] : https://access.redhat.com/errata/RHSA-2026:41019 
│                       │      │                  ├ [50] : https://access.redhat.com/errata/RHSA-2026:41030 
│                       │      │                  ├ [51] : https://access.redhat.com/errata/RHSA-2026:41031 
│                       │      │                  ├ [52] : https://access.redhat.com/errata/RHSA-2026:41036 
│                       │      │                  ├ [53] : https://access.redhat.com/errata/RHSA-2026:41055 
│                       │      │                  ├ [54] : https://access.redhat.com/errata/RHSA-2026:41066 
│                       │      │                  ├ [55] : https://access.redhat.com/errata/RHSA-2026:41928 
│                       │      │                  ├ [56] : https://access.redhat.com/errata/RHSA-2026:41930 
│                       │      │                  ├ [57] : https://access.redhat.com/errata/RHSA-2026:42043 
│                       │      │                  ├ [58] : https://access.redhat.com/errata/RHSA-2026:42047 
│                       │      │                  ├ [59] : https://access.redhat.com/errata/RHSA-2026:42048 
│                       │      │                  ├ [60] : https://access.redhat.com/errata/RHSA-2026:42049 
│                       │      │                  ├ [61] : https://access.redhat.com/errata/RHSA-2026:42050 
│                       │      │                  ├ [62] : https://access.redhat.com/errata/RHSA-2026:42051 
│                       │      │                  ├ [63] : https://access.redhat.com/errata/RHSA-2026:42078 
│                       │      │                  ├ [64] : https://access.redhat.com/errata/RHSA-2026:42079 
│                       │      │                  ├ [65] : https://access.redhat.com/errata/RHSA-2026:42080 
│                       │      │                  ├ [66] : https://access.redhat.com/errata/RHSA-2026:42082 
│                       │      │                  ├ [67] : https://access.redhat.com/errata/RHSA-2026:42132 
│                       │      │                  ├ [68] : https://access.redhat.com/errata/RHSA-2026:42142 
│                       │      │                  ├ [69] : https://access.redhat.com/errata/RHSA-2026:42146 
│                       │      │                  ├ [70] : https://access.redhat.com/errata/RHSA-2026:42150 
│                       │      │                  ├ [71] : https://access.redhat.com/errata/RHSA-2026:42151 
│                       │      │                  ├ [72] : https://access.redhat.com/errata/RHSA-2026:42240 
│                       │      │                  ├ [73] : https://access.redhat.com/errata/RHSA-2026:42644 
│                       │      │                  ├ [74] : https://access.redhat.com/errata/RHSA-2026:42796 
│                       │      │                  ├ [75] : https://access.redhat.com/errata/RHSA-2026:42852 
│                       │      │                  ├ [76] : https://access.redhat.com/errata/RHSA-2026:43038 
│                       │      │                  ├ [77] : https://access.redhat.com/errata/RHSA-2026:43052 
│                       │      │                  ├ [78] : https://access.redhat.com/errata/RHSA-2026:43692 
│                       │      │                  ├ [79] : https://access.redhat.com/errata/RHSA-2026:44622 
│                       │      │                  ├ [80] : https://access.redhat.com/errata/RHSA-2026:44624 
│                       │      │                  ├ [81] : https://access.redhat.com/errata/RHSA-2026:46395 
│                       │      │                  ├ [82] : https://access.redhat.com/errata/RHSA-2026:47149 
│                       │      │                  ├ [83] : https://access.redhat.com/errata/RHSA-2026:47735 
│                       │      │                  ├ [84] : https://access.redhat.com/errata/RHSA-2026:47737 
│                       │      │                  ├ [85] : https://access.redhat.com/errata/RHSA-2026:47952 
│                       │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:50300 
│                       │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:50843 
│                       │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:51033 
│                       │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:51112 
│                       │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:51187 
│                       │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:51194 
│                       │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:51341 
│                       │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:52826 
│                       │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:53374 
│                       │      │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:53412 
│                       │      │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:53413 
│                       │      │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:53415 
│                       │      │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:53530 
│                       │      │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:54191 
│                       │      │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:54274 
│                       │      │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:54283 
│                       │      │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:54284 
│                       │      │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:54285 
│                       │      │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:54286 
│                       │      │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:54287 
│                       │      │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:54395 
│                       │      │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:54401 
│                       │      │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:54435 
│                       │      │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:54441 
│                       │      │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:54531 
│                       │      │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:54580 
│                       │      │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:54757 
│                       │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:56143 
│                       │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:56223 
│                       │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:56340 
│                       │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:56431 
│                       │      │                  ├ [117]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │      │                  ├ [118]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [119]: https://bugzilla.redhat.com/2484207 
│                       │      │                  ├ [120]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │      │                  ├ [121]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │      │                  ├ [122]: https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [123]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39821 
│                       │      │                  ├ [124]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39822 
│                       │      │                  ├ [125]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
│                       │      │                  ├ [126]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │      │                  ├ [127]: https://github.com/golang/go/issues/78760 
│                       │      │                  ├ [128]: https://go.dev/cl/767220 
│                       │      │                  ├ [129]: https://go.dev/issue/78760 
│                       │      │                  ├ [130]: https://groups.google.com/g/golang-announce/c/94pEor
│                       │      │                  │        npRlI 
│                       │      │                  ├ [131]: https://groups.google.com/g/golang-announce/c/iI-mYS
│                       │      │                  │        I0lu8 
│                       │      │                  ├ [132]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │      │                  ├ [133]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │      │                  ├ [134]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │      │                  ├ [135]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │      │                  ├ [136]: https://security.access.redhat.com/data/csaf/v2/vex/
│                       │      │                  │        2026/cve-2026-39821.json 
│                       │      │                  ├ [137]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │      │                  ╰ [138]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │      ╰ LastModifiedDate: 2026-08-19T12:18:01.253Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39822 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:c5ff32951cb505044c3393d917f97a2535a9b0334a39e4bd0ab26
│                       │      │                   f9c17ba74c1 
│                       │      ├ Title           : golang: Go os.Root: Symlink following vulnerability allows
│                       │      │                   directory traversal 
│                       │      ├ Description     : On Unix systems, opening a file in an os.Root improperly
│                       │      │                   follows symlinks to locations outside of the Root when the
│                       │      │                   final path component of the a path is a symbolic link and
│                       │      │                   the path ends in /. For example, 'root.Open("symlink/")'
│                       │      │                   will open "symlink" even when "symlink" is a symbolic link
│                       │      │                   pointing outside of the root. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-61 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 2 
│                       │      │                  ├ azure      : 3 
│                       │      │                  ├ bitnami    : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ photon     : 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ╰ rocky      : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 7.8 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                            │           H/A:H 
│                       │      │                            ╰ V3Score : 7.8 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38495 
│                       │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:38878 
│                       │      │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2026-39822 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2498152 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │      │                  ├ [5] : https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39822 
│                       │      │                  ├ [7] : https://errata.almalinux.org/10/ALSA-2026-38495.html 
│                       │      │                  ├ [8] : https://errata.rockylinux.org/RLSA-2026:38878 
│                       │      │                  ├ [9] : https://go.dev/cl/797880 
│                       │      │                  ├ [10]: https://go.dev/issue/79005 
│                       │      │                  ├ [11]: https://groups.google.com/g/golang-announce/c/OrmQE_Y
│                       │      │                  │       p5Sc 
│                       │      │                  ├ [12]: https://linux.oracle.com/cve/CVE-2026-39822.html 
│                       │      │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
│                       │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
│                       │      │                  ├ [15]: https://pkg.go.dev/vuln/GO-2026-4970 
│                       │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
│                       │      ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
│                       │      ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:89cf33413d304fa30989bd680dd9d337d499e6c97c6f95d86f2ea
│                       │      │                   3e8b5a5a180 
│                       │      ├ Title           : mime: golang: Golang MIME: Denial of Service via
│                       │      │                   maliciously-crafted MIME header 
│                       │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid encoded-words can consume excessive CPU. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ╭ amazon : 2 
│                       │      │                  ├ azure  : 3 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42504 
│                       │      │                  ├ [1]: https://go.dev/cl/774481 
│                       │      │                  ├ [2]: https://go.dev/issue/79217 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42504 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │      ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-46600 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:c77a8a1b80c1609adc42333071b6a6655321ffc64bd93d61a5095
│                       │      │                   39ed71ec0c8 
│                       │      ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │      │                   invalid DNS record parsing 
│                       │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │      │                   of a parameter value overflows the message buffer. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-125 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │      │                  ├ [1]: https://go.dev/cl/786345 
│                       │      │                  ├ [2]: https://go.dev/issue/79795 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:55.673Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-56853 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:05b4d65edeb101e43144874c9796ecc9932e532ebe1ec2f1cae7b
│                       │      │                   bf14bf51de5 
│                       │      ├ Title           : net/http: golang: Go net/http: Unencrypted HTTP/2
│                       │      │                   connections vulnerable to Denial of Service 
│                       │      ├ Description     : When a server is configured to support unencrypted HTTP/2,
│                       │      │                   it reads a few bytes from each new connection to see if they
│                       │      │                    contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │      │                   unexpectedly not being applied when doing this. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56853 
│                       │      │                  ├ [1]: https://go.dev/cl/795540 
│                       │      │                  ├ [2]: https://go.dev/issue/80205 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56853 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56853 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.21Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-56858 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:40a08e4d1ed39123f6c29a06b432b40bb5ce38faf771c5054c3f9
│                       │      │                   e935c52aff9 
│                       │      ├ Title           : html/template: golang: Go html/template: Cross-Site
│                       │      │                   Scripting via pathological input 
│                       │      ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │      │                    early, allowing for attack-controlled data to inject
│                       │      │                   arbitrary content, potentially leading to XSS. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
│                       │      │                            │           H/A:N 
│                       │      │                            ╰ V3Score : 8.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56858 
│                       │      │                  ├ [1]: https://go.dev/cl/807100 
│                       │      │                  ├ [2]: https://go.dev/issue/80435 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56858 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56858 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.367Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-56859 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:ce1987a76c0a5502d3eeff37e472ca4c26e561bae8af73ad28b7f
│                       │      │                   0cb0ed2a43a 
│                       │      ├ Title           : encoding/xml: golang: Go: Denial of Service via XML decoding
│                       │      │                    recursion depth issue 
│                       │      ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │      │                   causing it to never fire; this could lead to stack
│                       │      │                   exhaustion. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56859 
│                       │      │                  ├ [1]: https://go.dev/cl/803320 
│                       │      │                  ├ [2]: https://go.dev/issue/80481 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56859 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56859 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.523Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-56860 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4cd8dbc08fea958a3f95bf9f7e97c9e9590a8d838e8929db2a9d8
│                       │      │                   0337bc96892 
│                       │      ├ Title           : net/url: golang: golang net/url: Denial of Service from
│                       │      │                   quadratic complexity in path resolution 
│                       │      ├ Description     : Previously, resolving relative paths containing parent
│                       │      │                   directory ('..') segments performed string conversions and
│                       │      │                   buffer rewrites on each step, resulting in quadratic time
│                       │      │                   complexity and high memory allocation overhead. Now, path
│                       │      │                   resolution operates on a byte buffer using index-based
│                       │      │                   backtracking for '..' segments, eliminating the quadratic
│                       │      │                   time complexity and significantly reducing memory
│                       │      │                   allocations. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 5.9 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56860 
│                       │      │                  ├ [1]: https://go.dev/cl/803681 
│                       │      │                  ├ [2]: https://go.dev/issue/80494 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56860 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56860 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T17:19:13.91Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-56862 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6090 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:a9bdf2a06e25be4006289c6ee4f6705fb37ba87c45afb58390ec2
│                       │      │                   cb39a55f21f 
│                       │      ├ Title           : crypto/tls: golang: Golang crypto/tls: Denial of Service via
│                       │      │                    indefinite KeyUpdate messages 
│                       │      ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                       │      │                    as state-advancing, regardless of whether a handshake has
│                       │      │                   been completed or not. As a result, a malicious client can
│                       │      │                   keep sending KeyUpdate messages to force the server to keep
│                       │      │                   performing key derivation operations indefinitely. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56862 
│                       │      │                  ├ [1]: https://go.dev/cl/804261 
│                       │      │                  ├ [2]: https://go.dev/issue/80528 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56862 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6090 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56862 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                       │      ╰ LastModifiedDate: 2026-08-14T16:16:57.717Z 
│                       ├ [12] ╭ VulnerabilityID : CVE-2026-42505 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5856 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                       │      │                  │         ed4b6e528ef06426e7e6 
│                       │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                       │      │                            31a9c14fa546310a9eba 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:abf8cf3110a749c39100a8210dd9bec77cad15e86ca49b41811aa
│                       │      │                   8fba98bdf82 
│                       │      ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
│                       │      │                    Encrypted Client Hello 
│                       │      ├ Description     : Handshakes which used Encrypted Client Hello could be
│                       │      │                   de-anonymized by a passive network observer due to a
│                       │      │                   disclosure of pre-shared key identities in the unencrypted
│                       │      │                   client hello. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-201 
│                       │      ├ VendorSeverity   ╭ alma   : 3 
│                       │      │                  ├ amazon : 2 
│                       │      │                  ├ azure  : 2 
│                       │      │                  ├ bitnami: 2 
│                       │      │                  ├ photon : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/errata/RHSA-2026:37436 
│                       │      │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2026-42505 
│                       │      │                  ├ [2]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [3]: https://errata.almalinux.org/10/ALSA-2026-37436.html 
│                       │      │                  ├ [4]: https://go.dev/cl/775960 
│                       │      │                  ├ [5]: https://go.dev/issue/79282 
│                       │      │                  ├ [6]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp
│                       │      │                  │      5Sc 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
│                       │      │                  ├ [8]: https://pkg.go.dev/vuln/GO-2026-5856 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
│                       │      ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
│                       │      ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
│                       ╰ [13] ╭ VulnerabilityID : CVE-2026-42507 
│                              ├ VendorIDs        ─ [0]: GO-2026-5039 
│                              ├ PkgID           : stdlib@v1.26.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                              │                  ╰ UID : f77aad5d3fa73e61 
│                              ├ InstalledVersion: v1.26.3 
│                              ├ FixedVersion    : 1.25.11, 1.26.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
│                              │                  │         ed4b6e528ef06426e7e6 
│                              │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
│                              │                            31a9c14fa546310a9eba 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:1cac810efcc25287e8770ccf10f3320fcaf34495c37c8218b2e52
│                              │                   d85346c8ed2 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ alma       : 2 
│                              │                  ├ amazon     : 2 
│                              │                  ├ azure      : 2 
│                              │                  ├ bitnami    : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ photon     : 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29980 
│                              │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:29981 
│                              │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [3] : https://bugzilla.redhat.com/2484205 
│                              │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
│                              │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                              │                  ├ [6] : https://creativecommons.org/licenses/by/4.0/ 
│                              │                  ├ [7] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-27145 
│                              │                  ├ [8] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-42507 
│                              │                  ├ [9] : https://errata.almalinux.org/10/ALSA-2026-29980.html 
│                              │                  ├ [10]: https://errata.rockylinux.org/RLSA-2026:29981 
│                              │                  ├ [11]: https://go.dev/cl/777060 
│                              │                  ├ [12]: https://go.dev/issue/79346 
│                              │                  ├ [13]: https://groups.google.com/g/golang-announce/c/tKs3rmc
│                              │                  │       BcKw 
│                              │                  ├ [14]: https://linux.oracle.com/cve/CVE-2026-42507.html 
│                              │                  ├ [15]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                              │                  ├ [16]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [17]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                              ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                              ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
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
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:629e37d776f17e75ad58610fe3315f4b55b9e5b11778b3493f138
                        │      │                   5ba75b9248b 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:37123 
                        │      │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2026-25681 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2466505 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2466507 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2467822 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2480761 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2480680 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2480685 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480688 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480757 
                        │      │                  ├ [14]: https://bugzilla.redhat.com/show_bug.cgi?id=2480761 
                        │      │                  ├ [15]: https://bugzilla.redhat.com/show_bug.cgi?id=2493620 
                        │      │                  ├ [16]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [24]: https://errata.almalinux.org/10/ALSA-2026-34357.html 
                        │      │                  ├ [25]: https://errata.rockylinux.org/RLSA-2026:37123 
                        │      │                  ├ [26]: https://go.dev/cl/781703 
                        │      │                  ├ [27]: https://go.dev/issue/79574 
                        │      │                  ├ [28]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [29]: https://linux.oracle.com/cve/CVE-2026-25681.html 
                        │      │                  ├ [30]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [31]: https://nvd.nist.gov/vuln/detail/CVE-2026-25681 
                        │      │                  ├ [32]: https://pkg.go.dev/vuln/GO-2026-5029 
                        │      │                  ╰ [33]: https://www.cve.org/CVERecord?id=CVE-2026-25681 
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
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:934acfcba21f9e1190ebe3a9653f40163b97d8306514ec9db09ee
                        │      │                   2e71089ee0a 
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
                        │      │                  ├ [16]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25681 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27136 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [20]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39832 
                        │      │                  ├ [21]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39835 
                        │      │                  ├ [22]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42508 
                        │      │                  ├ [23]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-57231 
                        │      │                  ├ [24]: https://errata.almalinux.org/9/ALSA-2026-37123.html 
                        │      │                  ├ [25]: https://errata.rockylinux.org/RLSA-2026:37123 
                        │      │                  ├ [26]: https://go.dev/cl/781685 
                        │      │                  ├ [27]: https://go.dev/issue/79575 
                        │      │                  ├ [28]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [29]: https://linux.oracle.com/cve/CVE-2026-27136.html 
                        │      │                  ├ [30]: https://linux.oracle.com/errata/ELSA-2026-37123.html 
                        │      │                  ├ [31]: https://nvd.nist.gov/vuln/detail/CVE-2026-27136 
                        │      │                  ├ [32]: https://pkg.go.dev/vuln/GO-2026-5030 
                        │      │                  ╰ [33]: https://www.cve.org/CVERecord?id=CVE-2026-27136 
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
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:636a75ecd950f74fcf4c61d7cd48e18bc20daea2e45f73add5f22
                        │      │                   88ccd9601f1 
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
                        │      │                  ├ [10]: https://access.redhat.com/errata/RHSA-2026:50205 
                        │      │                  ├ [11]: https://access.redhat.com/errata/RHSA-2026:54274 
                        │      │                  ├ [12]: https://access.redhat.com/errata/RHSA-2026:54283 
                        │      │                  ├ [13]: https://access.redhat.com/errata/RHSA-2026:54284 
                        │      │                  ├ [14]: https://access.redhat.com/errata/RHSA-2026:54285 
                        │      │                  ├ [15]: https://access.redhat.com/errata/RHSA-2026:54286 
                        │      │                  ├ [16]: https://access.redhat.com/errata/RHSA-2026:54287 
                        │      │                  ├ [17]: https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [18]: https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [19]: https://github.com/golang/go/issues/78476 
                        │      │                  ├ [20]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [21]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [22]: https://go.dev/cl/761581 
                        │      │                  ├ [23]: https://go.dev/cl/761640 
                        │      │                  ├ [24]: https://go.dev/issue/78476 
                        │      │                  ├ [25]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [26]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [27]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [28]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [29]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [30]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [31]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [32]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [33]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [34]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [35]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-08-19T12:17:53.54Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f11ad2910fd3abf5fecde2a24dfd5aeb757ce2c77b8a0ccee5908
                        │      │                   e65fdf0151a 
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
                        │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:50300 
                        │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:50843 
                        │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:51033 
                        │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:51112 
                        │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:51187 
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:51194 
                        │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:51341 
                        │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:52826 
                        │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:53374 
                        │      │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:53412 
                        │      │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:53413 
                        │      │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:53415 
                        │      │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:53530 
                        │      │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:54191 
                        │      │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:54274 
                        │      │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:54283 
                        │      │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:54284 
                        │      │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:54285 
                        │      │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:54286 
                        │      │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:54287 
                        │      │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:54395 
                        │      │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:54401 
                        │      │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:54435 
                        │      │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:54441 
                        │      │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:54531 
                        │      │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:54580 
                        │      │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:54757 
                        │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:56143 
                        │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:56223 
                        │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:56340 
                        │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:56431 
                        │      │                  ├ [117]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [118]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [119]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [120]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [121]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [122]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [123]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39821 
                        │      │                  ├ [124]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39822 
                        │      │                  ├ [125]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
                        │      │                  ├ [126]: https://errata.rockylinux.org/RLSA-2026:37435 
                        │      │                  ├ [127]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [128]: https://go.dev/cl/767220 
                        │      │                  ├ [129]: https://go.dev/issue/78760 
                        │      │                  ├ [130]: https://groups.google.com/g/golang-announce/c/94pEor
                        │      │                  │        npRlI 
                        │      │                  ├ [131]: https://groups.google.com/g/golang-announce/c/iI-mYS
                        │      │                  │        I0lu8 
                        │      │                  ├ [132]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [133]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [134]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [135]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [136]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-39821.json 
                        │      │                  ├ [137]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [138]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-08-19T12:18:01.253Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.56.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:60701ab412d61a1c752368fb650f4bcec9b51d14d979c8ad6042e
                        │      │                   ae49751eb1e 
                        │      ├ Title           : golang.org/x/net/dns/dnsmessage:
                        │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
                        │      │                   invalid DNS record parsing 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-125 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
                        │      │                  ├ [1]: https://go.dev/cl/786345 
                        │      │                  ├ [2]: https://go.dev/issue/79795 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
                        │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:55.673Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:235dac27690f883d5d694aecdb25293010abf3b24b65ba8d7b7a1
                        │      │                   885c71deb6a 
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
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-42502 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5027 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:57a515b567d4cb45ff8331be32fc131324edf7d9836617e355fde
                        │      │                   209dddf3562 
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
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-42506 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5025 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:58ba23aaa5c7d355271e97c2fbb98384039997a6e074a06487ff2
                        │      │                   2f03c9049b8 
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
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-39824 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5024 
                        │      ├ PkgID           : golang.org/x/sys@v0.42.0 
                        │      ├ PkgName         : golang.org/x/sys 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/sys@v0.42.0 
                        │      │                  ╰ UID : 9dd104bb9b94dda4 
                        │      ├ InstalledVersion: v0.42.0 
                        │      ├ FixedVersion    : 0.44.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:24b90715b7f5c2d5d8960112ddff49cd4be3f861ad579008e0709
                        │      │                   364a92ccd83 
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
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5979bc5fe46b0aa05244a25f0f3044be7873e548b2755d5d5a043
                        │      │                   8359b7e5432 
                        │      ├ Title           : golang.org/x/text: golang.org/x/text: Denial of Service via
                        │      │                   invalid UTF-8 input 
                        │      ├ Description     : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing invalid UTF-8 bytes. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56852 
                        │      │                  ├ [1]: https://go.dev/cl/794100 
                        │      │                  ├ [2]: https://go.dev/issue/80142 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-56852 
                        │      │                  ├ [4]: https://pkg.go.dev/vuln/GO-2026-5970 
                        │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-56852 
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
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:3a1bace9fe378dda2f3337c06a6716e95ccf93127181f6c659dec
                        │      │                   9abbf747383 
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
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:10481ec5477a064a72f53cc67e1ac2ebdd71c01fec8d56806e60a
                        │      │                   38b628d336d 
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
                        │      │                  ├ azure      : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
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
                        │      │                  ├ [38]: https://access.redhat.com/errata/RHSA-2026:49703 
                        │      │                  ├ [39]: https://access.redhat.com/errata/RHSA-2026:49705 
                        │      │                  ├ [40]: https://access.redhat.com/errata/RHSA-2026:49729 
                        │      │                  ├ [41]: https://access.redhat.com/errata/RHSA-2026:49744 
                        │      │                  ├ [42]: https://access.redhat.com/errata/RHSA-2026:49765 
                        │      │                  ├ [43]: https://access.redhat.com/errata/RHSA-2026:49770 
                        │      │                  ├ [44]: https://access.redhat.com/errata/RHSA-2026:50205 
                        │      │                  ├ [45]: https://access.redhat.com/errata/RHSA-2026:50319 
                        │      │                  ├ [46]: https://access.redhat.com/errata/RHSA-2026:51057 
                        │      │                  ├ [47]: https://access.redhat.com/errata/RHSA-2026:51187 
                        │      │                  ├ [48]: https://access.redhat.com/errata/RHSA-2026:52946 
                        │      │                  ├ [49]: https://access.redhat.com/errata/RHSA-2026:53374 
                        │      │                  ├ [50]: https://access.redhat.com/errata/RHSA-2026:53412 
                        │      │                  ├ [51]: https://access.redhat.com/errata/RHSA-2026:53413 
                        │      │                  ├ [52]: https://access.redhat.com/errata/RHSA-2026:53415 
                        │      │                  ├ [53]: https://access.redhat.com/errata/RHSA-2026:53416 
                        │      │                  ├ [54]: https://access.redhat.com/errata/RHSA-2026:53530 
                        │      │                  ├ [55]: https://access.redhat.com/errata/RHSA-2026:54168 
                        │      │                  ├ [56]: https://access.redhat.com/errata/RHSA-2026:54401 
                        │      │                  ├ [57]: https://access.redhat.com/errata/RHSA-2026:54427 
                        │      │                  ├ [58]: https://access.redhat.com/errata/RHSA-2026:54432 
                        │      │                  ├ [59]: https://access.redhat.com/errata/RHSA-2026:54435 
                        │      │                  ├ [60]: https://access.redhat.com/errata/RHSA-2026:54441 
                        │      │                  ├ [61]: https://access.redhat.com/errata/RHSA-2026:54500 
                        │      │                  ├ [62]: https://access.redhat.com/errata/RHSA-2026:54525 
                        │      │                  ├ [63]: https://access.redhat.com/errata/RHSA-2026:54531 
                        │      │                  ├ [64]: https://access.redhat.com/errata/RHSA-2026:54603 
                        │      │                  ├ [65]: https://access.redhat.com/errata/RHSA-2026:54757 
                        │      │                  ├ [66]: https://access.redhat.com/errata/RHSA-2026:55899 
                        │      │                  ├ [67]: https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [68]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [69]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [70]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [71]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [72]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [73]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [74]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [75]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
                        │      │                  ├ [76]: https://errata.rockylinux.org/RLSA-2026:36317 
                        │      │                  ├ [77]: https://go.dev/cl/783621 
                        │      │                  ├ [78]: https://go.dev/issue/79694 
                        │      │                  ├ [79]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [80]: https://linux.oracle.com/cve/CVE-2026-27145.html 
                        │      │                  ├ [81]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [82]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [83]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [84]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [85]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-08-19T12:17:39.17Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-33818 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5972 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d18c8246831460c8efede7ae0a5ef56fe8340c2d2046974ba4135
                        │      │                   073ed265162 
                        │      ├ Title           : encoding/asn1: golang: Go encoding/asn1: Denial of Service
                        │      │                   via excessive recursion in Unmarshal 
                        │      ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
                        │      │                   exhaustion when parsing deeply-nested, recursive
                        │      │                   structures. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-400 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33818 
                        │      │                  ├ [1]: https://go.dev/cl/814980 
                        │      │                  ├ [2]: https://go.dev/issue/80405 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33818 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5972 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-33818 
                        │      ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:55.317Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:a3b0cfc1f525531762ab17f4ae59b440df174cc6d3414d48407f4
                        │      │                   075b22d6ea9 
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
                        │      │                  ├ [86] : https://access.redhat.com/errata/RHSA-2026:50300 
                        │      │                  ├ [87] : https://access.redhat.com/errata/RHSA-2026:50843 
                        │      │                  ├ [88] : https://access.redhat.com/errata/RHSA-2026:51033 
                        │      │                  ├ [89] : https://access.redhat.com/errata/RHSA-2026:51112 
                        │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:51187 
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:51194 
                        │      │                  ├ [92] : https://access.redhat.com/errata/RHSA-2026:51341 
                        │      │                  ├ [93] : https://access.redhat.com/errata/RHSA-2026:52826 
                        │      │                  ├ [94] : https://access.redhat.com/errata/RHSA-2026:53374 
                        │      │                  ├ [95] : https://access.redhat.com/errata/RHSA-2026:53412 
                        │      │                  ├ [96] : https://access.redhat.com/errata/RHSA-2026:53413 
                        │      │                  ├ [97] : https://access.redhat.com/errata/RHSA-2026:53415 
                        │      │                  ├ [98] : https://access.redhat.com/errata/RHSA-2026:53530 
                        │      │                  ├ [99] : https://access.redhat.com/errata/RHSA-2026:54191 
                        │      │                  ├ [100]: https://access.redhat.com/errata/RHSA-2026:54274 
                        │      │                  ├ [101]: https://access.redhat.com/errata/RHSA-2026:54283 
                        │      │                  ├ [102]: https://access.redhat.com/errata/RHSA-2026:54284 
                        │      │                  ├ [103]: https://access.redhat.com/errata/RHSA-2026:54285 
                        │      │                  ├ [104]: https://access.redhat.com/errata/RHSA-2026:54286 
                        │      │                  ├ [105]: https://access.redhat.com/errata/RHSA-2026:54287 
                        │      │                  ├ [106]: https://access.redhat.com/errata/RHSA-2026:54395 
                        │      │                  ├ [107]: https://access.redhat.com/errata/RHSA-2026:54401 
                        │      │                  ├ [108]: https://access.redhat.com/errata/RHSA-2026:54435 
                        │      │                  ├ [109]: https://access.redhat.com/errata/RHSA-2026:54441 
                        │      │                  ├ [110]: https://access.redhat.com/errata/RHSA-2026:54531 
                        │      │                  ├ [111]: https://access.redhat.com/errata/RHSA-2026:54580 
                        │      │                  ├ [112]: https://access.redhat.com/errata/RHSA-2026:54757 
                        │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:56143 
                        │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:56223 
                        │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:56340 
                        │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:56431 
                        │      │                  ├ [117]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [118]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [119]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [120]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [121]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [122]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [123]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39821 
                        │      │                  ├ [124]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39822 
                        │      │                  ├ [125]: https://errata.almalinux.org/10/ALSA-2026-46395.html 
                        │      │                  ├ [126]: https://errata.rockylinux.org/RLSA-2026:37435 
                        │      │                  ├ [127]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [128]: https://go.dev/cl/767220 
                        │      │                  ├ [129]: https://go.dev/issue/78760 
                        │      │                  ├ [130]: https://groups.google.com/g/golang-announce/c/94pEor
                        │      │                  │        npRlI 
                        │      │                  ├ [131]: https://groups.google.com/g/golang-announce/c/iI-mYS
                        │      │                  │        I0lu8 
                        │      │                  ├ [132]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [133]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [134]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [135]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [136]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-39821.json 
                        │      │                  ├ [137]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [138]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-08-19T12:18:01.253Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-39822 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4970 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:a47e7b26d5f9bc92907dac70ef129c4d22f26de502dddf76ed228
                        │      │                   1e829d0dd7e 
                        │      ├ Title           : golang: Go os.Root: Symlink following vulnerability allows
                        │      │                   directory traversal 
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
                        │      │                  ├ azure      : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ photon     : 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 7.8 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                            │           H/A:H 
                        │      │                            ╰ V3Score : 7.8 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38495 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:38878 
                        │      │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2026-39822 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2498152 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [5] : https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39822 
                        │      │                  ├ [7] : https://errata.almalinux.org/10/ALSA-2026-38495.html 
                        │      │                  ├ [8] : https://errata.rockylinux.org/RLSA-2026:38878 
                        │      │                  ├ [9] : https://go.dev/cl/797880 
                        │      │                  ├ [10]: https://go.dev/issue/79005 
                        │      │                  ├ [11]: https://groups.google.com/g/golang-announce/c/OrmQE_Y
                        │      │                  │       p5Sc 
                        │      │                  ├ [12]: https://linux.oracle.com/cve/CVE-2026-39822.html 
                        │      │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
                        │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
                        │      │                  ├ [15]: https://pkg.go.dev/vuln/GO-2026-4970 
                        │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
                        │      ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:abdbcd679276b00adbda4e6b10576b0abb6988e24418d85726970
                        │      │                   8d508e90e98 
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
                        ├ [16] ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3873cb29a3ad6d59e640d2ee33b80e596b508879c290e96718dc4
                        │      │                   9a294677077 
                        │      ├ Title           : golang.org/x/net/dns/dnsmessage:
                        │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
                        │      │                   invalid DNS record parsing 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-125 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
                        │      │                  ├ [1]: https://go.dev/cl/786345 
                        │      │                  ├ [2]: https://go.dev/issue/79795 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
                        │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:55.673Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2026-56853 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6089 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8634aafbe298983b667f4efe168f8f9719fb5c6f70d078f51fec1
                        │      │                   ed2bfc81dff 
                        │      ├ Title           : net/http: golang: Go net/http: Unencrypted HTTP/2
                        │      │                   connections vulnerable to Denial of Service 
                        │      ├ Description     : When a server is configured to support unencrypted HTTP/2,
                        │      │                   it reads a few bytes from each new connection to see if they
                        │      │                    contain the HTTP/2 client preface. ReadHeaderTimeout is
                        │      │                   unexpectedly not being applied when doing this. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56853 
                        │      │                  ├ [1]: https://go.dev/cl/795540 
                        │      │                  ├ [2]: https://go.dev/issue/80205 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56853 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6089 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56853 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:57.21Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2026-56858 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6091 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:70897c3840a87edf4fca2509c6c438b77654ef7e0e598aa49e718
                        │      │                   1df2372a9f9 
                        │      ├ Title           : html/template: golang: Go html/template: Cross-Site
                        │      │                   Scripting via pathological input 
                        │      ├ Description     : Previously, pathological inputs could close an unescaped '/'
                        │      │                    early, allowing for attack-controlled data to inject
                        │      │                   arbitrary content, potentially leading to XSS. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ bitnami: 2 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
                        │      │                            │           H/A:N 
                        │      │                            ╰ V3Score : 8.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56858 
                        │      │                  ├ [1]: https://go.dev/cl/807100 
                        │      │                  ├ [2]: https://go.dev/issue/80435 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56858 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6091 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56858 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:57.367Z 
                        ├ [19] ╭ VulnerabilityID : CVE-2026-56859 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6088 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:6ac4972e1cf3766f256c91ee9786c21c95ce0a4394b2c83b14953
                        │      │                   d288a5f85a4 
                        │      ├ Title           : encoding/xml: golang: Go: Denial of Service via XML decoding
                        │      │                    recursion depth issue 
                        │      ├ Description     : Previously, DecodeElement would reset the depth counter
                        │      │                   causing it to never fire; this could lead to stack
                        │      │                   exhaustion. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56859 
                        │      │                  ├ [1]: https://go.dev/cl/803320 
                        │      │                  ├ [2]: https://go.dev/issue/80481 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56859 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6088 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56859 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:57.523Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2026-56860 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6218 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0f7805eb7f674d4ca712621496098ddde7a221da3611e1b5a73bb
                        │      │                   2e238b15fab 
                        │      ├ Title           : net/url: golang: golang net/url: Denial of Service from
                        │      │                   quadratic complexity in path resolution 
                        │      ├ Description     : Previously, resolving relative paths containing parent
                        │      │                   directory ('..') segments performed string conversions and
                        │      │                   buffer rewrites on each step, resulting in quadratic time
                        │      │                   complexity and high memory allocation overhead. Now, path
                        │      │                   resolution operates on a byte buffer using index-based
                        │      │                   backtracking for '..' segments, eliminating the quadratic
                        │      │                   time complexity and significantly reducing memory
                        │      │                   allocations. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-407 
                        │      ├ VendorSeverity   ╭ bitnami: 2 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 5.9 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56860 
                        │      │                  ├ [1]: https://go.dev/cl/803681 
                        │      │                  ├ [2]: https://go.dev/issue/80494 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56860 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6218 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56860 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
                        │      ╰ LastModifiedDate: 2026-08-14T17:19:13.91Z 
                        ├ [21] ╭ VulnerabilityID : CVE-2026-56862 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6090 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:425a2f9297f67feb7d1518f9f8f95fd8436e06214d873db46548f
                        │      │                   de85f20d07d 
                        │      ├ Title           : crypto/tls: golang: Golang crypto/tls: Denial of Service via
                        │      │                    indefinite KeyUpdate messages 
                        │      ├ Description     : Handshake messages, such as KeyUpdate, are always considered
                        │      │                    as state-advancing, regardless of whether a handshake has
                        │      │                   been completed or not. As a result, a malicious client can
                        │      │                   keep sending KeyUpdate messages to force the server to keep
                        │      │                   performing key derivation operations indefinitely. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-56862 
                        │      │                  ├ [1]: https://go.dev/cl/804261 
                        │      │                  ├ [2]: https://go.dev/issue/80528 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-56862 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-6090 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-56862 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
                        │      ╰ LastModifiedDate: 2026-08-14T16:16:57.717Z 
                        ├ [22] ╭ VulnerabilityID : CVE-2026-42505 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5856 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                        │      │                  │         ed4b6e528ef06426e7e6 
                        │      │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                        │      │                            31a9c14fa546310a9eba 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:969a3ccdbb4df2080c0e6056855bfeffb3bcaf9fad8ee48fe94a2
                        │      │                   06346bb48eb 
                        │      ├ Title           : crypto/tls: golang: Go crypto/tls: Information disclosure in
                        │      │                    Encrypted Client Hello 
                        │      ├ Description     : Handshakes which used Encrypted Client Hello could be
                        │      │                   de-anonymized by a passive network observer due to a
                        │      │                   disclosure of pre-shared key identities in the unencrypted
                        │      │                   client hello. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-201 
                        │      ├ VendorSeverity   ╭ alma   : 3 
                        │      │                  ├ amazon : 2 
                        │      │                  ├ azure  : 2 
                        │      │                  ├ bitnami: 2 
                        │      │                  ├ photon : 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://access.redhat.com/errata/RHSA-2026:37436 
                        │      │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2026-42505 
                        │      │                  ├ [2]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [3]: https://errata.almalinux.org/10/ALSA-2026-37436.html 
                        │      │                  ├ [4]: https://go.dev/cl/775960 
                        │      │                  ├ [5]: https://go.dev/issue/79282 
                        │      │                  ├ [6]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp
                        │      │                  │      5Sc 
                        │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
                        │      │                  ├ [8]: https://pkg.go.dev/vuln/GO-2026-5856 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
                        │      ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
                        ╰ [23] ╭ VulnerabilityID : CVE-2026-42507 
                               ├ VendorIDs        ─ [0]: GO-2026-5039 
                               ├ PkgID           : stdlib@v1.26.3 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                               │                  ╰ UID : 9770e92adf1be71b 
                               ├ InstalledVersion: v1.26.3 
                               ├ FixedVersion    : 1.25.11, 1.26.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:7ec304fbd94a2b5c486f728eb4797f0f7b913791d535
                               │                  │         ed4b6e528ef06426e7e6 
                               │                  ╰ DiffID: sha256:73ded5bb577800e2138be8bbbf26b0239868fe8c63f2
                               │                            31a9c14fa546310a9eba 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:874a143c8678f840add2c584d55f226eccd5af8d70cd77b972aab
                               │                   e076d74a2f7 
                               ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                               │                   error messages via input injection 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : MEDIUM 
                               ├ VendorSeverity   ╭ alma       : 2 
                               │                  ├ amazon     : 2 
                               │                  ├ azure      : 2 
                               │                  ├ bitnami    : 2 
                               │                  ├ oracle-oval: 2 
                               │                  ├ photon     : 2 
                               │                  ├ redhat     : 2 
                               │                  ╰ rocky      : 2 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 5.3 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                            │           L/A:N 
                               │                            ╰ V3Score : 5.3 
                               ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29980 
                               │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:29981 
                               │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2026-42507 
                               │                  ├ [3] : https://bugzilla.redhat.com/2484205 
                               │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
                               │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                               │                  ├ [6] : https://creativecommons.org/licenses/by/4.0/ 
                               │                  ├ [7] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                               │                  │       26-27145 
                               │                  ├ [8] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                               │                  │       26-42507 
                               │                  ├ [9] : https://errata.almalinux.org/10/ALSA-2026-29980.html 
                               │                  ├ [10]: https://errata.rockylinux.org/RLSA-2026:29981 
                               │                  ├ [11]: https://go.dev/cl/777060 
                               │                  ├ [12]: https://go.dev/issue/79346 
                               │                  ├ [13]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                               │                  │       BcKw 
                               │                  ├ [14]: https://linux.oracle.com/cve/CVE-2026-42507.html 
                               │                  ├ [15]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
                               │                  ├ [16]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                               │                  ├ [17]: https://pkg.go.dev/vuln/GO-2026-5039 
                               │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
```

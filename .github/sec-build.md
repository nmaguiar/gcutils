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
│                             ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                             │                  │         c06d02b3f27769e975d 
│                             │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                             │                            d7e7f1ae38c060a2e08 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-49844 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:f162ddcd04b5e0d5837c7e4b5ae59783109b0a825422be4c0f224a
│                             │                   c66adc966f 
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
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:1fd7ac2ba4edfecbee7c74e8e62637e7580e1d741da02900a17fb8
│                       │     │                   3bbebedc29 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-39821 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:7486137fdb5bf2aa278a59043138b792f0559a08d0eb0b1fd694b0
│                       │     │                   6772117177 
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
│                       │     │                  ├ [110]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │     │                  ├ [111]: https://bugzilla.redhat.com/2480756 
│                       │     │                  ├ [112]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │     │                  ├ [113]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │     │                  ├ [114]: https://creativecommons.org/licenses/by/4.0/ 
│                       │     │                  ├ [115]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39821 
│                       │     │                  ├ [116]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39822 
│                       │     │                  ├ [117]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
│                       │     │                  ├ [118]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │     │                  ├ [119]: https://github.com/golang/go/issues/78760 
│                       │     │                  ├ [120]: https://go.dev/cl/767220 
│                       │     │                  ├ [121]: https://go.dev/issue/78760 
│                       │     │                  ├ [122]: https://groups.google.com/g/golang-announce/c/94pEorn
│                       │     │                  │        pRlI 
│                       │     │                  ├ [123]: https://groups.google.com/g/golang-announce/c/iI-mYSI
│                       │     │                  │        0lu8 
│                       │     │                  ├ [124]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │     │                  ├ [125]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │     │                  ├ [126]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │     │                  ├ [127]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │     │                  ├ [128]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │     │                  │        026/cve-2026-39821.json 
│                       │     │                  ├ [129]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │     │                  ╰ [130]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │     ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:19.973Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:408c65b70607123182e64366525fe2d751f1e455c2229c13d726e0
│                       │     │                   b0ee102550 
│                       │     ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │     │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │     │                   invalid DNS record parsing 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ VendorSeverity   ─ redhat: 3 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │     │                  ├ [1]: https://go.dev/cl/786345 
│                       │     │                  ├ [2]: https://go.dev/issue/79795 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:21.913Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-33818 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:3c098c2fa17140a756b3743743e6e1b463ab4010329e6ef5e1d299
│                       │     │                   4f86d88282 
│                       │     ├ Title           : Enforce maximum recursion depth in encoding/asn1 
│                       │     ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │     │                   exhaustion when parsing deeply-nested, recursive
│                       │     │                   structures. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/814980 
│                       │     │                  ├ [1]: https://go.dev/issue/80405 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:19.84Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-56853 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:239228d0fa37e3ae0722ded81b1181987208aa127d9415b1f01d91
│                       │     │                   1e52bfbf43 
│                       │     ├ Title           : Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check
│                       │     │                   in net/http 
│                       │     ├ Description     : When a server is configured to support unencrypted HTTP/2, it
│                       │     │                    reads a few bytes from each new connection to see if they
│                       │     │                   contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │     │                   unexpectedly not being applied when doing this. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/795540 
│                       │     │                  ├ [1]: https://go.dev/issue/80205 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.093Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-56858 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:916dd35426b725159a54a65effa9ec955a842d9e77325c32221d92
│                       │     │                   9c78ece33d 
│                       │     ├ Title           : Fix Javascript regexp context tracking in html/template 
│                       │     ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │     │                   early, allowing for attack-controlled data to inject
│                       │     │                   arbitrary content, potentially leading to XSS. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/807100 
│                       │     │                  ├ [1]: https://go.dev/issue/80435 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.207Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-56859 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:84b10b14f9c8d549f6cd41ac186fc5c1973cda32f73e550bc2f732
│                       │     │                   800dfd563e 
│                       │     ├ Title           : Add recursion depth guard during decode in encoding/xml 
│                       │     ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │     │                   causing it to never fire; this could lead to stack
│                       │     │                   exhaustion. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/803320 
│                       │     │                  ├ [1]: https://go.dev/issue/80481 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.32Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56860 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : 8ff0a998c454a030 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:11998abd55fb995b3bfdb10568458a1cf842928aa2dfb21c18dafc
│                       │     │                   73b48f7078 
│                       │     ├ Title           : Avoid quadratic complexity in resolvePath in net/url 
│                       │     ├ Description     : Previously, resolving relative paths containing parent
│                       │     │                   directory ('..') segments performed string conversions and
│                       │     │                   buffer rewrites on each step, resulting in quadratic time
│                       │     │                   complexity and high memory allocation overhead. Now, path
│                       │     │                   resolution operates on a byte buffer using index-based
│                       │     │                   backtracking for '..' segments, eliminating the quadratic
│                       │     │                   time complexity and significantly reducing memory
│                       │     │                   allocations. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/803681 
│                       │     │                  ├ [1]: https://go.dev/issue/80494 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.44Z 
│                       ╰ [8] ╭ VulnerabilityID : CVE-2026-56862 
│                             ├ VendorIDs        ─ [0]: GO-2026-6090 
│                             ├ PkgID           : stdlib@v1.26.5 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                             │                  ╰ UID : 8ff0a998c454a030 
│                             ├ InstalledVersion: v1.26.5 
│                             ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                             │                  │         c06d02b3f27769e975d 
│                             │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                             │                            d7e7f1ae38c060a2e08 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:842e7372e79edddc1fffba1a5f1b9a2765afbe2b2c8b9284af1530
│                             │                   7088f98bc1 
│                             ├ Title           : Limit handshake messages we are willing to accept
│                             │                   post-handshake in crypto/tls 
│                             ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                             │                   as state-advancing, regardless of whether a handshake has
│                             │                   been completed or not. As a result, a malicious client can
│                             │                   keep sending KeyUpdate messages to force the server to keep
│                             │                   performing key derivation operations indefinitely. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/804261 
│                             │                  ├ [1]: https://go.dev/issue/80528 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6090 
│                             ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                             ╰ LastModifiedDate: 2026-08-13T22:17:22.55Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ef278f49207fe079358eed75df112432de64d6ea9395bfa2191f74
│                       │     │                   e12ebbdd7f 
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
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-39821 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:23599350376c5d0a8ee33fbe1dfb55b08afbf830fe4ecc421a9927
│                       │     │                   09a2aebfc7 
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
│                       │     │                  ├ [110]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │     │                  ├ [111]: https://bugzilla.redhat.com/2480756 
│                       │     │                  ├ [112]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │     │                  ├ [113]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │     │                  ├ [114]: https://creativecommons.org/licenses/by/4.0/ 
│                       │     │                  ├ [115]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39821 
│                       │     │                  ├ [116]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │     │                  │        26-39822 
│                       │     │                  ├ [117]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
│                       │     │                  ├ [118]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │     │                  ├ [119]: https://github.com/golang/go/issues/78760 
│                       │     │                  ├ [120]: https://go.dev/cl/767220 
│                       │     │                  ├ [121]: https://go.dev/issue/78760 
│                       │     │                  ├ [122]: https://groups.google.com/g/golang-announce/c/94pEorn
│                       │     │                  │        pRlI 
│                       │     │                  ├ [123]: https://groups.google.com/g/golang-announce/c/iI-mYSI
│                       │     │                  │        0lu8 
│                       │     │                  ├ [124]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │     │                  ├ [125]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │     │                  ├ [126]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │     │                  ├ [127]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │     │                  ├ [128]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │     │                  │        026/cve-2026-39821.json 
│                       │     │                  ├ [129]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │     │                  ╰ [130]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │     ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:19.973Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-46600 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:277f26292dfd22e987dff51fde38703568d6ba62eb531d177c5aa1
│                       │     │                   ee9c5962a6 
│                       │     ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │     │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │     │                   invalid DNS record parsing 
│                       │     ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │     │                   of a parameter value overflows the message buffer. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-125 
│                       │     ├ VendorSeverity   ─ redhat: 3 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │     │                  ├ [1]: https://go.dev/cl/786345 
│                       │     │                  ├ [2]: https://go.dev/issue/79795 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │     │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │     ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:21.913Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-33818 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:5587e082b317c8335d43ff78eac2f4d9416d1db555d3de835fa87e
│                       │     │                   3ab7f46158 
│                       │     ├ Title           : Enforce maximum recursion depth in encoding/asn1 
│                       │     ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │     │                   exhaustion when parsing deeply-nested, recursive
│                       │     │                   structures. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/814980 
│                       │     │                  ├ [1]: https://go.dev/issue/80405 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:19.84Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-56853 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:15425852a8ec8d71cb12f412fa14c58019e8fddb7ee452f42d2ac9
│                       │     │                   bc94b36ea2 
│                       │     ├ Title           : Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check
│                       │     │                   in net/http 
│                       │     ├ Description     : When a server is configured to support unencrypted HTTP/2, it
│                       │     │                    reads a few bytes from each new connection to see if they
│                       │     │                   contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │     │                   unexpectedly not being applied when doing this. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/795540 
│                       │     │                  ├ [1]: https://go.dev/issue/80205 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.093Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-56858 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:ebdd3bf2721145b8114e9315533b639945a4455655450ee7e47649
│                       │     │                   109e1b03b9 
│                       │     ├ Title           : Fix Javascript regexp context tracking in html/template 
│                       │     ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │     │                   early, allowing for attack-controlled data to inject
│                       │     │                   arbitrary content, potentially leading to XSS. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/807100 
│                       │     │                  ├ [1]: https://go.dev/issue/80435 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.207Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-56859 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:322a7ad7306e592e0b063f2db29f5a531ca220c5da5cb6a225fe48
│                       │     │                   26e20b1c29 
│                       │     ├ Title           : Add recursion depth guard during decode in encoding/xml 
│                       │     ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │     │                   causing it to never fire; this could lead to stack
│                       │     │                   exhaustion. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/803320 
│                       │     │                  ├ [1]: https://go.dev/issue/80481 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.32Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-56860 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │     ├ PkgID           : stdlib@v1.26.5 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │     │                  ╰ UID : b28b13f09fb71390 
│                       │     ├ InstalledVersion: v1.26.5 
│                       │     ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                       │     │                  │         c06d02b3f27769e975d 
│                       │     │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                       │     │                            d7e7f1ae38c060a2e08 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:71223683dbaa483be80385dd9a218c9c2ba43ecb5adf1ee75562e9
│                       │     │                   7474f76b39 
│                       │     ├ Title           : Avoid quadratic complexity in resolvePath in net/url 
│                       │     ├ Description     : Previously, resolving relative paths containing parent
│                       │     │                   directory ('..') segments performed string conversions and
│                       │     │                   buffer rewrites on each step, resulting in quadratic time
│                       │     │                   complexity and high memory allocation overhead. Now, path
│                       │     │                   resolution operates on a byte buffer using index-based
│                       │     │                   backtracking for '..' segments, eliminating the quadratic
│                       │     │                   time complexity and significantly reducing memory
│                       │     │                   allocations. 
│                       │     ├ Severity        : UNKNOWN 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/803681 
│                       │     │                  ├ [1]: https://go.dev/issue/80494 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │     ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │     ╰ LastModifiedDate: 2026-08-13T22:17:22.44Z 
│                       ╰ [8] ╭ VulnerabilityID : CVE-2026-56862 
│                             ├ VendorIDs        ─ [0]: GO-2026-6090 
│                             ├ PkgID           : stdlib@v1.26.5 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                             │                  ╰ UID : b28b13f09fb71390 
│                             ├ InstalledVersion: v1.26.5 
│                             ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d471
│                             │                  │         c06d02b3f27769e975d 
│                             │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6a
│                             │                            d7e7f1ae38c060a2e08 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:74ec50c0715fcd07ae41df582a23b9986c1299cace2b8fdff02dab
│                             │                   16ca9cb2ad 
│                             ├ Title           : Limit handshake messages we are willing to accept
│                             │                   post-handshake in crypto/tls 
│                             ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                             │                   as state-advancing, regardless of whether a handshake has
│                             │                   been completed or not. As a result, a malicious client can
│                             │                   keep sending KeyUpdate messages to force the server to keep
│                             │                   performing key derivation operations indefinitely. 
│                             ├ Severity        : UNKNOWN 
│                             ├ References       ╭ [0]: https://go.dev/cl/804261 
│                             │                  ├ [1]: https://go.dev/issue/80528 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornpRlI 
│                             │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6090 
│                             ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                             ╰ LastModifiedDate: 2026-08-13T22:17:22.55Z 
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
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:b20ec4a6ed77877e81b99b0285e7c6a5aea25ef554fdae42fd73f
│                       │      │                   0de91397f8c 
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
│                       │      ╰ LastModifiedDate: 2026-08-13T13:17:54.363Z 
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
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:23a93a62bd77bc1bb761276b7a20d9adc66e9cc1137f9160a0099
│                       │      │                   dac4bb50bac 
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
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:ab84e369e118e7ba0bd4f6115bf30623f119f2332b1a37f46a324
│                       │      │                   1301415f130 
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
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-39821 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:26c6a8be9ba6dc0297316f276be9c9b8debfb58ce5420fcb9a290
│                       │      │                   a09534064b6 
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
│                       │      │                  ├ [110]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │      │                  ├ [111]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [112]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │      │                  ├ [113]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │      │                  ├ [114]: https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [115]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39821 
│                       │      │                  ├ [116]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39822 
│                       │      │                  ├ [117]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
│                       │      │                  ├ [118]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │      │                  ├ [119]: https://github.com/golang/go/issues/78760 
│                       │      │                  ├ [120]: https://go.dev/cl/767220 
│                       │      │                  ├ [121]: https://go.dev/issue/78760 
│                       │      │                  ├ [122]: https://groups.google.com/g/golang-announce/c/94pEor
│                       │      │                  │        npRlI 
│                       │      │                  ├ [123]: https://groups.google.com/g/golang-announce/c/iI-mYS
│                       │      │                  │        I0lu8 
│                       │      │                  ├ [124]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │      │                  ├ [125]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │      │                  ├ [126]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │      │                  ├ [127]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │      │                  ├ [128]: https://security.access.redhat.com/data/csaf/v2/vex/
│                       │      │                  │        2026/cve-2026-39821.json 
│                       │      │                  ├ [129]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │      │                  ╰ [130]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:19.973Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-46600 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:1659ef5a2a28788f85b58370ea2f7fc55c47212eb3d7aa7de5564
│                       │      │                   17df13843f7 
│                       │      ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │      │                   invalid DNS record parsing 
│                       │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │      │                   of a parameter value overflows the message buffer. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-125 
│                       │      ├ VendorSeverity   ─ redhat: 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │      │                  ├ [1]: https://go.dev/cl/786345 
│                       │      │                  ├ [2]: https://go.dev/issue/79795 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:21.913Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-33818 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:12ffb8dfc838392faaf23c997adb97dcee125d48136d9f0102846
│                       │      │                   1c24fb3efce 
│                       │      ├ Title           : Enforce maximum recursion depth in encoding/asn1 
│                       │      ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │      │                   exhaustion when parsing deeply-nested, recursive
│                       │      │                   structures. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/814980 
│                       │      │                  ├ [1]: https://go.dev/issue/80405 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:19.84Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-56853 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:959d075d8169878fbd81a11854420fe984d404ac2b018047ba8d6
│                       │      │                   fda27777e29 
│                       │      ├ Title           : Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check
│                       │      │                   in net/http 
│                       │      ├ Description     : When a server is configured to support unencrypted HTTP/2,
│                       │      │                   it reads a few bytes from each new connection to see if they
│                       │      │                    contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │      │                   unexpectedly not being applied when doing this. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/795540 
│                       │      │                  ├ [1]: https://go.dev/issue/80205 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.093Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-56858 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:19e1ad26444342c303eb53946ce909e5135c3ce15325af399a63f
│                       │      │                   922983d4e52 
│                       │      ├ Title           : Fix Javascript regexp context tracking in html/template 
│                       │      ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │      │                    early, allowing for attack-controlled data to inject
│                       │      │                   arbitrary content, potentially leading to XSS. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/807100 
│                       │      │                  ├ [1]: https://go.dev/issue/80435 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.207Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-56859 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5514ff4ff86cab2c227ce2448b980f332168961f377d81a954f27
│                       │      │                   9e9f5b58871 
│                       │      ├ Title           : Add recursion depth guard during decode in encoding/xml 
│                       │      ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │      │                   causing it to never fire; this could lead to stack
│                       │      │                   exhaustion. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/803320 
│                       │      │                  ├ [1]: https://go.dev/issue/80481 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.32Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-56860 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │      ├ PkgID           : stdlib@v1.26.5 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                       │      │                  ╰ UID : 8a8a3a8f15e1f251 
│                       │      ├ InstalledVersion: v1.26.5 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:1566c04b3e15fe73f458d2bb2d14f28597070611abc32184b18cb
│                       │      │                   2d61f7b4e5f 
│                       │      ├ Title           : Avoid quadratic complexity in resolvePath in net/url 
│                       │      ├ Description     : Previously, resolving relative paths containing parent
│                       │      │                   directory ('..') segments performed string conversions and
│                       │      │                   buffer rewrites on each step, resulting in quadratic time
│                       │      │                   complexity and high memory allocation overhead. Now, path
│                       │      │                   resolution operates on a byte buffer using index-based
│                       │      │                   backtracking for '..' segments, eliminating the quadratic
│                       │      │                   time complexity and significantly reducing memory
│                       │      │                   allocations. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/803681 
│                       │      │                  ├ [1]: https://go.dev/issue/80494 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.44Z 
│                       ╰ [10] ╭ VulnerabilityID : CVE-2026-56862 
│                              ├ VendorIDs        ─ [0]: GO-2026-6090 
│                              ├ PkgID           : stdlib@v1.26.5 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.5 
│                              │                  ╰ UID : 8a8a3a8f15e1f251 
│                              ├ InstalledVersion: v1.26.5 
│                              ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                              │                  │         1c06d02b3f27769e975d 
│                              │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                              │                            ad7e7f1ae38c060a2e08 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:b8aa8bb677e923c11f5cf50f1a6b71cc333b541808336f1258143
│                              │                   4a8629b4c3e 
│                              ├ Title           : Limit handshake messages we are willing to accept
│                              │                   post-handshake in crypto/tls 
│                              ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                              │                    as state-advancing, regardless of whether a handshake has
│                              │                   been completed or not. As a result, a malicious client can
│                              │                   keep sending KeyUpdate messages to force the server to keep
│                              │                   performing key derivation operations indefinitely. 
│                              ├ Severity        : UNKNOWN 
│                              ├ References       ╭ [0]: https://go.dev/cl/804261 
│                              │                  ├ [1]: https://go.dev/issue/80528 
│                              │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                              │                  │      RlI 
│                              │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6090 
│                              ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                              ╰ LastModifiedDate: 2026-08-13T22:17:22.55Z 
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
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:7d1320be7ed9ffe539d2c96578ec483d3c5612341cea4f06c50d0
│                       │      │                   276a3ab9c4f 
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
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:ce054494042c4374a86ed51ce74adf890d2acc01ca56f17b303af
│                       │      │                   24b18cd7f5d 
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
│                       │      │                  ├ [63]: https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │      │                  ├ [64]: https://bugzilla.redhat.com/2445356 
│                       │      │                  ├ [65]: https://bugzilla.redhat.com/2484207 
│                       │      │                  ├ [66]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │      │                  ├ [67]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │      │                  ├ [68]: https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [69]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-25679 
│                       │      │                  ├ [70]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-27145 
│                       │      │                  ├ [71]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
│                       │      │                  ├ [72]: https://errata.rockylinux.org/RLSA-2026:36317 
│                       │      │                  ├ [73]: https://go.dev/cl/783621 
│                       │      │                  ├ [74]: https://go.dev/issue/79694 
│                       │      │                  ├ [75]: https://groups.google.com/g/golang-announce/c/tKs3rmc
│                       │      │                  │       BcKw 
│                       │      │                  ├ [76]: https://linux.oracle.com/cve/CVE-2026-27145.html 
│                       │      │                  ├ [77]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │      │                  ├ [78]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │      │                  ├ [79]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      │                  ├ [80]: https://security.access.redhat.com/data/csaf/v2/vex/2
│                       │      │                  │       026/cve-2026-27145.json 
│                       │      │                  ╰ [81]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T13:18:09.84Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-39821 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5026 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:e46a2e7672e96e8b2fdb58b16504d9c82ddb858b2944b64940d76
│                       │      │                   34d9d4c2975 
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
│                       │      │                  ├ [110]: https://access.redhat.com/security/cve/CVE-2026-39821 
│                       │      │                  ├ [111]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [112]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
│                       │      │                  ├ [113]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │      │                  ├ [114]: https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [115]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39821 
│                       │      │                  ├ [116]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
│                       │      │                  │        026-39822 
│                       │      │                  ├ [117]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
│                       │      │                  ├ [118]: https://errata.rockylinux.org/RLSA-2026:37435 
│                       │      │                  ├ [119]: https://github.com/golang/go/issues/78760 
│                       │      │                  ├ [120]: https://go.dev/cl/767220 
│                       │      │                  ├ [121]: https://go.dev/issue/78760 
│                       │      │                  ├ [122]: https://groups.google.com/g/golang-announce/c/94pEor
│                       │      │                  │        npRlI 
│                       │      │                  ├ [123]: https://groups.google.com/g/golang-announce/c/iI-mYS
│                       │      │                  │        I0lu8 
│                       │      │                  ├ [124]: https://linux.oracle.com/cve/CVE-2026-39821.html 
│                       │      │                  ├ [125]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
│                       │      │                  ├ [126]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
│                       │      │                  ├ [127]: https://pkg.go.dev/vuln/GO-2026-5026 
│                       │      │                  ├ [128]: https://security.access.redhat.com/data/csaf/v2/vex/
│                       │      │                  │        2026/cve-2026-39821.json 
│                       │      │                  ├ [129]: https://ubuntu.com/security/notices/USN-8416-1 
│                       │      │                  ╰ [130]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
│                       │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:19.973Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-39822 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4970 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:62fdbfe9014b298efc38c293a419bc5583ba707088eeb20d88d47
│                       │      │                   9d1d6999f41 
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
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38878 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39822 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2498152 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
│                       │      │                  ├ [4] : https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [5] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39822 
│                       │      │                  ├ [6] : https://errata.almalinux.org/9/ALSA-2026-38878.html 
│                       │      │                  ├ [7] : https://errata.rockylinux.org/RLSA-2026:38878 
│                       │      │                  ├ [8] : https://go.dev/cl/797880 
│                       │      │                  ├ [9] : https://go.dev/issue/79005 
│                       │      │                  ├ [10]: https://groups.google.com/g/golang-announce/c/OrmQE_Y
│                       │      │                  │       p5Sc 
│                       │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2026-39822.html 
│                       │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
│                       │      │                  ├ [13]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
│                       │      │                  ├ [14]: https://pkg.go.dev/vuln/GO-2026-4970 
│                       │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
│                       │      ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
│                       │      ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:c6d75e6a46fca576cde221f354ad8a60b36a2232e8b9696b451f1
│                       │      │                   d83d2a8631f 
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
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-46600 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5942 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b4808808d81c9543480e2da38bd93d54c7dab241ec4e86b298b78
│                       │      │                   60a7b27c587 
│                       │      ├ Title           : golang.org/x/net/dns/dnsmessage:
│                       │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
│                       │      │                   invalid DNS record parsing 
│                       │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
│                       │      │                   of a parameter value overflows the message buffer. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-125 
│                       │      ├ VendorSeverity   ─ redhat: 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
│                       │      │                  ├ [1]: https://go.dev/cl/786345 
│                       │      │                  ├ [2]: https://go.dev/issue/79795 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
│                       │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:21.913Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-42505 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5856 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:49db785ae27e90fa2f73cd24506cf218b7a98351924934113f294
│                       │      │                   1b454fcf7d9 
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
│                       │      ├ References       ╭ [0]: https://access.redhat.com/errata/RHSA-2026:37435 
│                       │      │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2026-42505 
│                       │      │                  ├ [2]: https://bugzilla.redhat.com/2480756 
│                       │      │                  ├ [3]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
│                       │      │                  ├ [4]: https://go.dev/cl/775960 
│                       │      │                  ├ [5]: https://go.dev/issue/79282 
│                       │      │                  ├ [6]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp
│                       │      │                  │      5Sc 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
│                       │      │                  ├ [8]: https://pkg.go.dev/vuln/GO-2026-5856 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
│                       │      ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
│                       │      ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-42507 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5039 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:442dffa61bc9a12185d3e52070b0bcb59b31c181b79b6ee84f8e9
│                       │      │                   dc5aee4b3b0 
│                       │      ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                       │      │                   error messages via input injection 
│                       │      ├ Description     : When returning errors, functions in the net/textproto
│                       │      │                   package would include its input as part of the error. This
│                       │      │                   might allow an attacker to inject misleading content to
│                       │      │                   errors that are printed or logged. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ amazon     : 2 
│                       │      │                  ├ azure      : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ photon     : 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ rocky      : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29981 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-42507 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2484205 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │      │                  ├ [5] : https://creativecommons.org/licenses/by/4.0/ 
│                       │      │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-27145 
│                       │      │                  ├ [7] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-42507 
│                       │      │                  ├ [8] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
│                       │      │                  ├ [9] : https://errata.rockylinux.org/RLSA-2026:29981 
│                       │      │                  ├ [10]: https://go.dev/cl/777060 
│                       │      │                  ├ [11]: https://go.dev/issue/79346 
│                       │      │                  ├ [12]: https://groups.google.com/g/golang-announce/c/tKs3rmc
│                       │      │                  │       BcKw 
│                       │      │                  ├ [13]: https://linux.oracle.com/cve/CVE-2026-42507.html 
│                       │      │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                       │      │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                       │      │                  ├ [16]: https://pkg.go.dev/vuln/GO-2026-5039 
│                       │      │                  ╰ [17]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                       │      ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-33818 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5972 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f491097dd00f9ce947b66a050774e1ac370100e109a31690ee0b1
│                       │      │                   04b80a9aee9 
│                       │      ├ Title           : Enforce maximum recursion depth in encoding/asn1 
│                       │      ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
│                       │      │                   exhaustion when parsing deeply-nested, recursive
│                       │      │                   structures. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/814980 
│                       │      │                  ├ [1]: https://go.dev/issue/80405 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5972 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:19.84Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-56853 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6089 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:0d794d0bc0f83939fb26dc20fb1ac779a716173bcbbc5be6d3652
│                       │      │                   8d642cd4420 
│                       │      ├ Title           : Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check
│                       │      │                   in net/http 
│                       │      ├ Description     : When a server is configured to support unencrypted HTTP/2,
│                       │      │                   it reads a few bytes from each new connection to see if they
│                       │      │                    contain the HTTP/2 client preface. ReadHeaderTimeout is
│                       │      │                   unexpectedly not being applied when doing this. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/795540 
│                       │      │                  ├ [1]: https://go.dev/issue/80205 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6089 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.093Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-56858 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6091 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:aad33766c9bfb3901569b282fb87bd22bc1e36bb081f68b1b0669
│                       │      │                   d51466f9820 
│                       │      ├ Title           : Fix Javascript regexp context tracking in html/template 
│                       │      ├ Description     : Previously, pathological inputs could close an unescaped '/'
│                       │      │                    early, allowing for attack-controlled data to inject
│                       │      │                   arbitrary content, potentially leading to XSS. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/807100 
│                       │      │                  ├ [1]: https://go.dev/issue/80435 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6091 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.207Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-56859 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6088 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:7d3f5b860b6d4abda7fa0ce08588e96c4e5fd26c783b9059c3642
│                       │      │                   11d9c01fb1d 
│                       │      ├ Title           : Add recursion depth guard during decode in encoding/xml 
│                       │      ├ Description     : Previously, DecodeElement would reset the depth counter
│                       │      │                   causing it to never fire; this could lead to stack
│                       │      │                   exhaustion. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/803320 
│                       │      │                  ├ [1]: https://go.dev/issue/80481 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6088 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.32Z 
│                       ├ [12] ╭ VulnerabilityID : CVE-2026-56860 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-6218 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : f77aad5d3fa73e61 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                       │      │                  │         1c06d02b3f27769e975d 
│                       │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                       │      │                            ad7e7f1ae38c060a2e08 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:6d86839b980a9bcf253e0c6b46b74f1542c8f0a4b4678f552d5d1
│                       │      │                   ec1a3e0772f 
│                       │      ├ Title           : Avoid quadratic complexity in resolvePath in net/url 
│                       │      ├ Description     : Previously, resolving relative paths containing parent
│                       │      │                   directory ('..') segments performed string conversions and
│                       │      │                   buffer rewrites on each step, resulting in quadratic time
│                       │      │                   complexity and high memory allocation overhead. Now, path
│                       │      │                   resolution operates on a byte buffer using index-based
│                       │      │                   backtracking for '..' segments, eliminating the quadratic
│                       │      │                   time complexity and significantly reducing memory
│                       │      │                   allocations. 
│                       │      ├ Severity        : UNKNOWN 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/803681 
│                       │      │                  ├ [1]: https://go.dev/issue/80494 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                       │      │                  │      RlI 
│                       │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6218 
│                       │      ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-08-13T22:17:22.44Z 
│                       ╰ [13] ╭ VulnerabilityID : CVE-2026-56862 
│                              ├ VendorIDs        ─ [0]: GO-2026-6090 
│                              ├ PkgID           : stdlib@v1.26.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                              │                  ╰ UID : f77aad5d3fa73e61 
│                              ├ InstalledVersion: v1.26.3 
│                              ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
│                              │                  │         1c06d02b3f27769e975d 
│                              │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
│                              │                            ad7e7f1ae38c060a2e08 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:0154a470ddd34a335d6bc19e25b5cc1abac37b0526f5b91ac25b1
│                              │                   1e083cd1827 
│                              ├ Title           : Limit handshake messages we are willing to accept
│                              │                   post-handshake in crypto/tls 
│                              ├ Description     : Handshake messages, such as KeyUpdate, are always considered
│                              │                    as state-advancing, regardless of whether a handshake has
│                              │                   been completed or not. As a result, a malicious client can
│                              │                   keep sending KeyUpdate messages to force the server to keep
│                              │                   performing key derivation operations indefinitely. 
│                              ├ Severity        : UNKNOWN 
│                              ├ References       ╭ [0]: https://go.dev/cl/804261 
│                              │                  ├ [1]: https://go.dev/issue/80528 
│                              │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
│                              │                  │      RlI 
│                              │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6090 
│                              ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
│                              ╰ LastModifiedDate: 2026-08-13T22:17:22.55Z 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:83ad2c05c715d5f335de7468928160938d054f08465bc19207b92
                        │      │                   996511ba9c5 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d28ada8dc2587e6ae84c0c1681adbaddbf7a86e9f6656029e0b8d
                        │      │                   7cae12800cb 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5ed69ac5cf1005e9a1c308ae54196994c22aa91c491579eb86c51
                        │      │                   e1d66fff920 
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
                        │      ╰ LastModifiedDate: 2026-08-13T13:18:25.52Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2b4f9e39b1548b0e389d7177558b345047edbaf8dba19fed93f67
                        │      │                   50ef8e31319 
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
                        │      │                  ├ [110]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [111]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [112]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [113]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [114]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [115]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39821 
                        │      │                  ├ [116]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39822 
                        │      │                  ├ [117]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [118]: https://errata.rockylinux.org/RLSA-2026:37435 
                        │      │                  ├ [119]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [120]: https://go.dev/cl/767220 
                        │      │                  ├ [121]: https://go.dev/issue/78760 
                        │      │                  ├ [122]: https://groups.google.com/g/golang-announce/c/94pEor
                        │      │                  │        npRlI 
                        │      │                  ├ [123]: https://groups.google.com/g/golang-announce/c/iI-mYS
                        │      │                  │        I0lu8 
                        │      │                  ├ [124]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [125]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [126]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [127]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [128]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-39821.json 
                        │      │                  ├ [129]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [130]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:19.973Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.56.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:3fa3563ffdde257557e93b218388252a70ee889c9c1cabda9098d
                        │      │                   95f99003de7 
                        │      ├ Title           : golang.org/x/net/dns/dnsmessage:
                        │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
                        │      │                   invalid DNS record parsing 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-125 
                        │      ├ VendorSeverity   ─ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
                        │      │                  ├ [1]: https://go.dev/cl/786345 
                        │      │                  ├ [2]: https://go.dev/issue/79795 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
                        │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:21.913Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e71e0c93f0ffa53f07518ccc3fd9f27e863413689eb8e6ff19086
                        │      │                   16c8e100c4c 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:662cd0444690036cc0fb6ce576a15fb5ef11f52cbfc13f00d0d61
                        │      │                   926f4bc8483 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2a8709fcb78d53bdfddc452f006f8f5ddf0aac7a2cf0000f98e11
                        │      │                   c67f892096d 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:62ec09941be9245170863419bf57939a35ab5786e80ca1f6e644d
                        │      │                   bd6cd7aec85 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56852 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:be300ce6e335bdbfbdaba48551595726caf7b1b4ab1d44e3b501d
                        │      │                   11c1d15e372 
                        │      ├ Title           : golang.org/x/text: golang.org/x/text: Denial of Service via
                        │      │                   invalid UTF-8 input 
                        │      ├ Description     : A norm.Iter can enter an infinite loop when handling input
                        │      │                   containing invalid UTF-8 bytes. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ╭ azure : 3 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://github.com/advisories/GHSA-hrxh-6v49-42gf 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:ae179cc5725b410c8495382f81f858c6b59a0c79f609de5330a6d
                        │      │                   febb3758ba4 
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
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cdf49e7d454f9a523783080a517c1cbd437e629f785ac58243f4e
                        │      │                   0ac9997f323 
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
                        │      │                  ├ [63]: https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [64]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [65]: https://bugzilla.redhat.com/2484207 
                        │      │                  ├ [66]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [67]: https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [68]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [69]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [70]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [71]: https://errata.almalinux.org/9/ALSA-2026-36317.html 
                        │      │                  ├ [72]: https://errata.rockylinux.org/RLSA-2026:36317 
                        │      │                  ├ [73]: https://go.dev/cl/783621 
                        │      │                  ├ [74]: https://go.dev/issue/79694 
                        │      │                  ├ [75]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [76]: https://linux.oracle.com/cve/CVE-2026-27145.html 
                        │      │                  ├ [77]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [78]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [79]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [80]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [81]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-08-13T13:18:09.84Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:50fa1a93f1ff304ce20ee538705ae5bd7f1b6b9aef6bdd1f72de1
                        │      │                   7fac6e3f05e 
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
                        │      │                  ├ [110]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [111]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [112]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [113]: https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [114]: https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [115]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39821 
                        │      │                  ├ [116]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-39822 
                        │      │                  ├ [117]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [118]: https://errata.rockylinux.org/RLSA-2026:37435 
                        │      │                  ├ [119]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [120]: https://go.dev/cl/767220 
                        │      │                  ├ [121]: https://go.dev/issue/78760 
                        │      │                  ├ [122]: https://groups.google.com/g/golang-announce/c/94pEor
                        │      │                  │        npRlI 
                        │      │                  ├ [123]: https://groups.google.com/g/golang-announce/c/iI-mYS
                        │      │                  │        I0lu8 
                        │      │                  ├ [124]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [125]: https://linux.oracle.com/errata/ELSA-2026-46395.html 
                        │      │                  ├ [126]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [127]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [128]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-39821.json 
                        │      │                  ├ [129]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [130]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:19.973Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-39822 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4970 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39822 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:44b7dafb289b33d319030ece9506ead06708b36aa30658231b745
                        │      │                   c7ab8d8ceae 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:38878 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39822 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2498152 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2498152 
                        │      │                  ├ [4] : https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [5] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39822 
                        │      │                  ├ [6] : https://errata.almalinux.org/9/ALSA-2026-38878.html 
                        │      │                  ├ [7] : https://errata.rockylinux.org/RLSA-2026:38878 
                        │      │                  ├ [8] : https://go.dev/cl/797880 
                        │      │                  ├ [9] : https://go.dev/issue/79005 
                        │      │                  ├ [10]: https://groups.google.com/g/golang-announce/c/OrmQE_Y
                        │      │                  │       p5Sc 
                        │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2026-39822.html 
                        │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2026-38995.html 
                        │      │                  ├ [13]: https://nvd.nist.gov/vuln/detail/CVE-2026-39822 
                        │      │                  ├ [14]: https://pkg.go.dev/vuln/GO-2026-4970 
                        │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2026-39822 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.31Z 
                        │      ╰ LastModifiedDate: 2026-07-13T14:54:26.317Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:556fc0f55cc57c51828c43436cc4abf887158425a0a61b787b67f
                        │      │                   32f19b983d1 
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
                        ├ [15] ╭ VulnerabilityID : CVE-2026-46600 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5942 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46600 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:482e6ab6a8e91f813bab24a1d59baf3ff6d4eb6878c91f32fa3b6
                        │      │                   71b92fb4a9f 
                        │      ├ Title           : golang.org/x/net/dns/dnsmessage:
                        │      │                   golang.org/x/net/dns/dnsmessage: Denial of Service via
                        │      │                   invalid DNS record parsing 
                        │      ├ Description     : Parsing an invalid SVCB or HTTPS RR can panic when the size
                        │      │                   of a parameter value overflows the message buffer. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-125 
                        │      ├ VendorSeverity   ─ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46600 
                        │      │                  ├ [1]: https://go.dev/cl/786345 
                        │      │                  ├ [2]: https://go.dev/issue/79795 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46600 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5942 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46600 
                        │      ├ PublishedDate   : 2026-07-21T20:17:01.213Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:21.913Z 
                        ├ [16] ╭ VulnerabilityID : CVE-2026-42505 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5856 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.12, 1.26.5, 1.27.0-rc.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42505 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c098bd492dde0b5fbcef08441d1929f5e5e82f95ef5097f8cb21b
                        │      │                   7b20e7692c0 
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
                        │      ├ References       ╭ [0]: https://access.redhat.com/errata/RHSA-2026:37435 
                        │      │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2026-42505 
                        │      │                  ├ [2]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [3]: https://errata.almalinux.org/9/ALSA-2026-37435.html 
                        │      │                  ├ [4]: https://go.dev/cl/775960 
                        │      │                  ├ [5]: https://go.dev/issue/79282 
                        │      │                  ├ [6]: https://groups.google.com/g/golang-announce/c/OrmQE_Yp
                        │      │                  │      5Sc 
                        │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42505 
                        │      │                  ├ [8]: https://pkg.go.dev/vuln/GO-2026-5856 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42505 
                        │      ├ PublishedDate   : 2026-07-08T17:17:21.497Z 
                        │      ╰ LastModifiedDate: 2026-07-13T17:05:36.303Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2026-42507 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5039 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:9a8760591b50f67ccbebe5dc05a0fb88d9899d7dda349bbef2baf
                        │      │                   dd7a4597955 
                        │      ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                        │      │                   error messages via input injection 
                        │      ├ Description     : When returning errors, functions in the net/textproto
                        │      │                   package would include its input as part of the error. This
                        │      │                   might allow an attacker to inject misleading content to
                        │      │                   errors that are printed or logged. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ azure      : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ photon     : 2 
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
                        │      │                  ├ [5] : https://creativecommons.org/licenses/by/4.0/ 
                        │      │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27145 
                        │      │                  ├ [7] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-42507 
                        │      │                  ├ [8] : https://errata.almalinux.org/9/ALSA-2026-29981.html 
                        │      │                  ├ [9] : https://errata.rockylinux.org/RLSA-2026:29981 
                        │      │                  ├ [10]: https://go.dev/cl/777060 
                        │      │                  ├ [11]: https://go.dev/issue/79346 
                        │      │                  ├ [12]: https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [13]: https://linux.oracle.com/cve/CVE-2026-42507.html 
                        │      │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2026-29981.html 
                        │      │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                        │      │                  ├ [16]: https://pkg.go.dev/vuln/GO-2026-5039 
                        │      │                  ╰ [17]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                        │      ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                        │      ╰ LastModifiedDate: 2026-07-22T19:10:00.12Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2026-33818 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5972 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33818 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:06ef9050f07099c2b38b63c161fc7a91175e4238f470094c40832
                        │      │                   5b796934761 
                        │      ├ Title           : Enforce maximum recursion depth in encoding/asn1 
                        │      ├ Description     : Enforce a recursion limit in Unmarshal to prevent stack
                        │      │                   exhaustion when parsing deeply-nested, recursive
                        │      │                   structures. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ References       ╭ [0]: https://go.dev/cl/814980 
                        │      │                  ├ [1]: https://go.dev/issue/80405 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-5972 
                        │      ├ PublishedDate   : 2026-08-13T22:17:19.84Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:19.84Z 
                        ├ [19] ╭ VulnerabilityID : CVE-2026-56853 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6089 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56853 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:86eb3dd7aa2ddef505daf0cae0113fd90b3e6b904803484fbc78d
                        │      │                   fde26a3960b 
                        │      ├ Title           : Apply ReadHeaderTimeout when doing unencrypted HTTP/2 check
                        │      │                   in net/http 
                        │      ├ Description     : When a server is configured to support unencrypted HTTP/2,
                        │      │                   it reads a few bytes from each new connection to see if they
                        │      │                    contain the HTTP/2 client preface. ReadHeaderTimeout is
                        │      │                   unexpectedly not being applied when doing this. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ References       ╭ [0]: https://go.dev/cl/795540 
                        │      │                  ├ [1]: https://go.dev/issue/80205 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6089 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.093Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:22.093Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2026-56858 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6091 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56858 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d574349595431db32a75a930731e277cde050a00438e666e4f4ed
                        │      │                   941fa16d01e 
                        │      ├ Title           : Fix Javascript regexp context tracking in html/template 
                        │      ├ Description     : Previously, pathological inputs could close an unescaped '/'
                        │      │                    early, allowing for attack-controlled data to inject
                        │      │                   arbitrary content, potentially leading to XSS. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ References       ╭ [0]: https://go.dev/cl/807100 
                        │      │                  ├ [1]: https://go.dev/issue/80435 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6091 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.207Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:22.207Z 
                        ├ [21] ╭ VulnerabilityID : CVE-2026-56859 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6088 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56859 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5e2a4e4d4c61faa7cef8677eaeccf1085a5fa2e7b805b94a6a122
                        │      │                   c669edf4995 
                        │      ├ Title           : Add recursion depth guard during decode in encoding/xml 
                        │      ├ Description     : Previously, DecodeElement would reset the depth counter
                        │      │                   causing it to never fire; this could lead to stack
                        │      │                   exhaustion. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ References       ╭ [0]: https://go.dev/cl/803320 
                        │      │                  ├ [1]: https://go.dev/issue/80481 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6088 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.32Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:22.32Z 
                        ├ [22] ╭ VulnerabilityID : CVE-2026-56860 
                        │      ├ VendorIDs        ─ [0]: GO-2026-6218 
                        │      ├ PkgID           : stdlib@v1.26.3 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                        │      │                  ╰ UID : 9770e92adf1be71b 
                        │      ├ InstalledVersion: v1.26.3 
                        │      ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                        │      │                  │         1c06d02b3f27769e975d 
                        │      │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                        │      │                            ad7e7f1ae38c060a2e08 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56860 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:6460df89d1fe123e7837f1e34008aa1992907cc92a5783c849020
                        │      │                   534a3996e6d 
                        │      ├ Title           : Avoid quadratic complexity in resolvePath in net/url 
                        │      ├ Description     : Previously, resolving relative paths containing parent
                        │      │                   directory ('..') segments performed string conversions and
                        │      │                   buffer rewrites on each step, resulting in quadratic time
                        │      │                   complexity and high memory allocation overhead. Now, path
                        │      │                   resolution operates on a byte buffer using index-based
                        │      │                   backtracking for '..' segments, eliminating the quadratic
                        │      │                   time complexity and significantly reducing memory
                        │      │                   allocations. 
                        │      ├ Severity        : UNKNOWN 
                        │      ├ References       ╭ [0]: https://go.dev/cl/803681 
                        │      │                  ├ [1]: https://go.dev/issue/80494 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
                        │      │                  │      RlI 
                        │      │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6218 
                        │      ├ PublishedDate   : 2026-08-13T22:17:22.44Z 
                        │      ╰ LastModifiedDate: 2026-08-13T22:17:22.44Z 
                        ╰ [23] ╭ VulnerabilityID : CVE-2026-56862 
                               ├ VendorIDs        ─ [0]: GO-2026-6090 
                               ├ PkgID           : stdlib@v1.26.3 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
                               │                  ╰ UID : 9770e92adf1be71b 
                               ├ InstalledVersion: v1.26.3 
                               ├ FixedVersion    : 1.25.13, 1.26.6, 1.27.0-rc.3 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:2dab7530f159cb7b87ab44ac20e7ec034853097b7d47
                               │                  │         1c06d02b3f27769e975d 
                               │                  ╰ DiffID: sha256:074d5aede7ee5a13f90a5c571875c6ff46ee6fa0a0a6
                               │                            ad7e7f1ae38c060a2e08 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-56862 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:5f47ebeeb6286c6cb2088cae3d41f79e0c5e81de7072ca97f20aa
                               │                   4f666c724b9 
                               ├ Title           : Limit handshake messages we are willing to accept
                               │                   post-handshake in crypto/tls 
                               ├ Description     : Handshake messages, such as KeyUpdate, are always considered
                               │                    as state-advancing, regardless of whether a handshake has
                               │                   been completed or not. As a result, a malicious client can
                               │                   keep sending KeyUpdate messages to force the server to keep
                               │                   performing key derivation operations indefinitely. 
                               ├ Severity        : UNKNOWN 
                               ├ References       ╭ [0]: https://go.dev/cl/804261 
                               │                  ├ [1]: https://go.dev/issue/80528 
                               │                  ├ [2]: https://groups.google.com/g/golang-announce/c/94pEornp
                               │                  │      RlI 
                               │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2026-6090 
                               ├ PublishedDate   : 2026-08-13T22:17:22.55Z 
                               ╰ LastModifiedDate: 2026-08-13T22:17:22.55Z 
```

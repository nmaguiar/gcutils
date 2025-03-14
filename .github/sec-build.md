````yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.22.0_alpha20250108) 
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
├ [4] ╭ Target         : usr/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-27144 
│                       │     ├ PkgID           : github.com/go-jose/go-jose/v3@v3.0.3 
│                       │     ├ PkgName         : github.com/go-jose/go-jose/v3 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/go-jose/go-jose/v3@v3.0.3 
│                       │     │                  ╰ UID : bed6d9eee9ef0072 
│                       │     ├ InstalledVersion: v3.0.3 
│                       │     ├ FixedVersion    : 3.0.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-27144 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : go-jose: Go JOSE's Parsing Vulnerable to Denial of Service 
│                       │     ├ Description     : Go JOSE provides an implementation of the Javascript Object
│                       │     │                   Signing and Encryption set of standards in Go, including
│                       │     │                   support for JSON Web Encryption (JWE), JSON Web Signature
│                       │     │                   (JWS), and JSON Web Token (JWT) standards. In versions on the
│                       │     │                    4.x branch prior to version 4.0.5, when parsing compact JWS
│                       │     │                   or JWE input, Go JOSE could use excessive memory. The code
│                       │     │                   used strings.Split(token, ".") to split JWT tokens, which is
│                       │     │                   vulnerable to excessive memory consumption when processing
│                       │     │                   maliciously crafted tokens with a large number of `.`
│                       │     │                   characters.  An attacker could exploit this by sending
│                       │     │                   numerous malformed tokens, leading to memory exhaustion and a
│                       │     │                    Denial of Service. Version 4.0.5 fixes this issue. As a
│                       │     │                   workaround, applications could pre-validate that payloads
│                       │     │                   passed to Go JOSE do not contain an excessive number of `.`
│                       │     │                   characters. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-770 
│                       │     ├ VendorSeverity   ╭ azure      : 2 
│                       │     │                  ├ cbl-mariner: 2 
│                       │     │                  ├ ghsa       : 2 
│                       │     │                  ╰ redhat     : 2 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2025-27144 
│                       │     │                  ├ [1]: https://github.com/go-jose/go-jose 
│                       │     │                  ├ [2]: https://github.com/go-jose/go-jose/commit/99b346cec4e86
│                       │     │                  │      d102284642c5dcbe9bb0cacfc22 
│                       │     │                  ├ [3]: https://github.com/go-jose/go-jose/releases/tag/v4.0.5 
│                       │     │                  ├ [4]: https://github.com/go-jose/go-jose/security/advisories/
│                       │     │                  │      GHSA-c6gw-w398-hv78 
│                       │     │                  ├ [5]: https://github.com/golang/go/issues/71490 
│                       │     │                  ├ [6]: https://go.dev/issue/71490 
│                       │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2025-27144 
│                       │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2025-27144 
│                       │     ├ PublishedDate   : 2025-02-24T23:15:11.427Z 
│                       │     ╰ LastModifiedDate: 2025-02-24T23:15:11.427Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2024-56323 
│                       │     ├ PkgID           : github.com/openfga/openfga@v1.6.2 
│                       │     ├ PkgName         : github.com/openfga/openfga 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.6.2 
│                       │     │                  ╰ UID : 9b19146cf4b99910 
│                       │     ├ InstalledVersion: v1.6.2 
│                       │     ├ FixedVersion    : 1.8.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-56323 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : OpenFGA Authorization Bypass 
│                       │     ├ Description     : OpenFGA is an authorization/permission engine. IN OpenFGA
│                       │     │                   v1.3.8 to v1.8.2 (Helm chart openfga-0.1.38 to
│                       │     │                   openfga-0.2.19, docker v1.3.8 to v.1.8.2)  are vulnerable to
│                       │     │                   authorization bypass under the following conditions: 1.
│                       │     │                   calling Check API or ListObjects with a model that uses
│                       │     │                   [conditions](https://openfga.dev/docs/modeling/conditions),
│                       │     │                   and 2. calling Check API or ListObjects API with [contextual
│                       │     │                   tuples](https://openfga.dev/docs/concepts#what-are-contextual
│                       │     │                   -tuples) that include conditions and 3. OpenFGA is configured
│                       │     │                    with caching enabled (`OPENFGA_CHECK_QUERY_CACHE_ENABLED`).
│                       │     │                   Users are advised to upgrade to v1.8.3. There are no known
│                       │     │                   workarounds for this vulnerability. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-285 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │     │                  ├ [1]: https://github.com/openfga/openfga/security/advisories/
│                       │     │                  │      GHSA-32q6-rr98-cjqv 
│                       │     │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2024-56323 
│                       │     │                  ╰ [3]: https://pkg.go.dev/vuln/GO-2025-3384 
│                       │     ├ PublishedDate   : 2025-01-13T22:15:14.447Z 
│                       │     ╰ LastModifiedDate: 2025-01-13T22:15:14.447Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2025-25196 
│                       │     ├ PkgID           : github.com/openfga/openfga@v1.6.2 
│                       │     ├ PkgName         : github.com/openfga/openfga 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.6.2 
│                       │     │                  ╰ UID : 9b19146cf4b99910 
│                       │     ├ InstalledVersion: v1.6.2 
│                       │     ├ FixedVersion    : 1.8.5 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-25196 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : OpenFGA Authorization Bypass 
│                       │     ├ Description     : OpenFGA is a high-performance and flexible
│                       │     │                   authorization/permission engine built for developers and
│                       │     │                   inspired by Google Zanzibar. OpenFGA < v1.8.4 (Helm chart <
│                       │     │                   openfga-0.2.22, docker < v.1.8.4) are vulnerable to
│                       │     │                   authorization bypass when certain Check and ListObject calls
│                       │     │                   are executed. Users on OpenFGA v1.8.4 or previous,
│                       │     │                   specifically under the following conditions are affected by
│                       │     │                   this authorization bypass vulnerability: 1. Calling Check API
│                       │     │                    or ListObjects with a model that has a relation directly
│                       │     │                   assignable to both public access AND userset with the same
│                       │     │                   type. 2. A type bound public access tuple is assigned to an
│                       │     │                   object. 3. userset tuple is not assigned to the same object.
│                       │     │                   and 4. Check request's user field is a userset that has the
│                       │     │                   same type as the type bound public access tuple's user type.
│                       │     │                   Users are advised to upgrade to v1.8.5 which is backwards
│                       │     │                   compatible. There are no known workarounds for this
│                       │     │                   vulnerability. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-285 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │     │                  ├ [1]: https://github.com/openfga/openfga/commit/0aee4f47e0c64
│                       │     │                  │      2de78831ceb27bb62b116f49588 
│                       │     │                  ├ [2]: https://github.com/openfga/openfga/security/advisories/
│                       │     │                  │      GHSA-g4v5-6f5p-m38j 
│                       │     │                  ╰ [3]: https://nvd.nist.gov/vuln/detail/CVE-2025-25196 
│                       │     ├ PublishedDate   : 2025-02-19T21:15:15.577Z 
│                       │     ╰ LastModifiedDate: 2025-02-19T21:15:15.577Z 
│                       ╰ [3] ╭ VulnerabilityID : CVE-2025-22870 
│                             ├ PkgID           : golang.org/x/net@v0.34.0 
│                             ├ PkgName         : golang.org/x/net 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.34.0 
│                             │                  ╰ UID : 68b0878189f36bdd 
│                             ├ InstalledVersion: v0.34.0 
│                             ├ FixedVersion    : 0.36.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                             │                  │         bd8cd23b37fd2554d3e 
│                             │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                             │                            980f52ffbcac00bc560 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22870 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : golang.org/x/net/http/httpproxy: golang.org/x/net/proxy: HTTP
│                             │                    Proxy bypass using IPv6 Zone IDs in golang.org/x/net 
│                             ├ Description     : Matching of hosts against proxy patterns can improperly treat
│                             │                    an IPv6 zone ID as a hostname component. For example, when
│                             │                   the NO_PROXY environment variable is set to "*.example.com",
│                             │                   a request to "[::1%25.example.com]:80` will incorrectly match
│                             │                    and not be proxied. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ ghsa  : 2 
│                             │                  ╰ redhat: 2 
│                             ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/
│                             │                           │           A:L 
│                             │                           ╰ V3Score : 4.4 
│                             ├ References       ╭ [0]: http://www.openwall.com/lists/oss-security/2025/03/07/2 
│                             │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2025-22870 
│                             │                  ├ [2]: https://go-review.googlesource.com/q/project:net 
│                             │                  ├ [3]: https://go.dev/cl/654697 
│                             │                  ├ [4]: https://go.dev/issue/71984 
│                             │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2025-22870 
│                             │                  ├ [6]: https://pkg.go.dev/vuln/GO-2025-3503 
│                             │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2025-22870 
│                             ├ PublishedDate   : 2025-03-12T19:15:38.31Z 
│                             ╰ LastModifiedDate: 2025-03-12T19:15:38.31Z 
├ [5] ╭ Target         : usr/bin/prometheus 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2024-35255 
│                       │     ├ PkgID           : github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.5.2 
│                       │     ├ PkgName         : github.com/Azure/azure-sdk-for-go/sdk/azidentity 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/azure/azure-sdk-for-go/sdk/azide
│                       │     │                  │       ntity@v1.5.2 
│                       │     │                  ╰ UID : 36ed01495109b474 
│                       │     ├ InstalledVersion: v1.5.2 
│                       │     ├ FixedVersion    : 1.6.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-35255 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : azure-identity: Azure Identity Libraries Elevation of
│                       │     │                   Privilege Vulnerability in
│                       │     │                   github.com/Azure/azure-sdk-for-go/sdk/azidentity 
│                       │     ├ Description     : Azure Identity Libraries and Microsoft Authentication Library
│                       │     │                    Elevation of Privilege Vulnerability 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-362 
│                       │     ├ VendorSeverity   ╭ amazon     : 3 
│                       │     │                  ├ azure      : 2 
│                       │     │                  ├ cbl-mariner: 2 
│                       │     │                  ├ ghsa       : 2 
│                       │     │                  ╰ redhat     : 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.5 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 5.5 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2024-35255 
│                       │     │                  ├ [1] : https://github.com/Azure/azure-sdk-for-go/commit/50774
│                       │     │                  │       cd9709905523136fb05e8c85a50e8984499 
│                       │     │                  ├ [2] : https://github.com/Azure/azure-sdk-for-java/commit/5bf
│                       │     │                  │       020d6ea056de40e2738e3647a4e06f902c18d 
│                       │     │                  ├ [3] : https://github.com/Azure/azure-sdk-for-js/commit/c6aa7
│                       │     │                  │       5d312ae463e744163cedfd8fc480cc8d492 
│                       │     │                  ├ [4] : https://github.com/Azure/azure-sdk-for-net/commit/9279
│                       │     │                  │       a4f38bf69b457cfb9b354f210e0a540a5c53 
│                       │     │                  ├ [5] : https://github.com/Azure/azure-sdk-for-python/commit/c
│                       │     │                  │       b065acd7d0f957327dc4f02d1646d4e51a94178 
│                       │     │                  ├ [6] : https://github.com/AzureAD/microsoft-authentication-li
│                       │     │                  │       brary-for-dotnet/issues/4806#issuecomment-2178960340 
│                       │     │                  ├ [7] : https://github.com/advisories/GHSA-m5vv-6r4h-3vj9 
│                       │     │                  ├ [8] : https://msrc.microsoft.com/update-guide/vulnerability/
│                       │     │                  │       CVE-2024-35255 
│                       │     │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2024-35255 
│                       │     │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2024-35255 
│                       │     ├ PublishedDate   : 2024-06-11T17:16:03.55Z 
│                       │     ╰ LastModifiedDate: 2024-11-21T09:20:01.923Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2024-41110 
│                       │     ├ PkgID           : github.com/docker/docker@v26.1.3+incompatible 
│                       │     ├ PkgName         : github.com/docker/docker 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v26.1.3%2Bincompat
│                       │     │                  │       ible 
│                       │     │                  ╰ UID : ccb2af30cfe7e8ea 
│                       │     ├ InstalledVersion: v26.1.3+incompatible 
│                       │     ├ FixedVersion    : 23.0.15, 26.1.5, 27.1.1, 25.0.6 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-41110 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : moby: Authz zero length regression 
│                       │     ├ Description     : Moby is an open-source project created by Docker for software
│                       │     │                    containerization. A security vulnerability has been detected
│                       │     │                    in certain versions of Docker Engine, which could allow an
│                       │     │                   attacker to bypass authorization plugins (AuthZ) under
│                       │     │                   specific circumstances. The base likelihood of this being
│                       │     │                   exploited is low.
│                       │     │                   
│                       │     │                   Using a specially-crafted API request, an Engine API client
│                       │     │                   could make the daemon forward the request or response to an
│                       │     │                   authorization plugin without the body. In certain
│                       │     │                   circumstances, the authorization plugin may allow a request
│                       │     │                   which it would have otherwise denied if the body had been
│                       │     │                   forwarded to it.
│                       │     │                   A security issue was discovered In 2018, where an attacker
│                       │     │                   could bypass AuthZ plugins using a specially crafted API
│                       │     │                   request. This could lead to unauthorized actions, including
│                       │     │                   privilege escalation. Although this issue was fixed in Docker
│                       │     │                    Engine v18.09.1 in January 2019, the fix was not carried
│                       │     │                   forward to later major versions, resulting in a regression.
│                       │     │                   Anyone who depends on authorization plugins that introspect
│                       │     │                   the request and/or response body to make access control
│                       │     │                   decisions is potentially impacted.
│                       │     │                   Docker EE v19.03.x and all versions of Mirantis Container
│                       │     │                   Runtime are not vulnerable.
│                       │     │                   docker-ce v27.1.1 containes patches to fix the vulnerability.
│                       │     │                    Patches have also been merged into the master, 19.03, 20.0,
│                       │     │                   23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is
│                       │     │                   unable to upgrade immediately, avoid using AuthZ plugins
│                       │     │                   and/or restrict access to the Docker API to trusted parties,
│                       │     │                   following the principle of least privilege. 
│                       │     ├ Severity        : CRITICAL 
│                       │     ├ CweIDs           ╭ [0]: CWE-187 
│                       │     │                  ├ [1]: CWE-444 
│                       │     │                  ╰ [2]: CWE-863 
│                       │     ├ VendorSeverity   ╭ amazon     : 3 
│                       │     │                  ├ azure      : 4 
│                       │     │                  ├ cbl-mariner: 4 
│                       │     │                  ├ ghsa       : 4 
│                       │     │                  ├ redhat     : 4 
│                       │     │                  ╰ ubuntu     : 3 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                  │        │           A:H 
│                       │     │                  │        ╰ V3Score : 10 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 9.9 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2024-41110 
│                       │     │                  ├ [1] : https://github.com/moby/moby 
│                       │     │                  ├ [2] : https://github.com/moby/moby/commit/411e817ddf710ff8e0
│                       │     │                  │       8fa193da80cb78af708191 
│                       │     │                  ├ [3] : https://github.com/moby/moby/commit/42f40b1d6dd7562342
│                       │     │                  │       f832b9cd2adf9e668eeb76 
│                       │     │                  ├ [4] : https://github.com/moby/moby/commit/65cc597cea28cdc25b
│                       │     │                  │       ea3b8a86384b4251872919 
│                       │     │                  ├ [5] : https://github.com/moby/moby/commit/852759a7df454cbf88
│                       │     │                  │       db4e954c919becd48faa9b 
│                       │     │                  ├ [6] : https://github.com/moby/moby/commit/a31260625655cff9ae
│                       │     │                  │       226b51757915e275e304b0 
│                       │     │                  ├ [7] : https://github.com/moby/moby/commit/a79fabbfe84117696a
│                       │     │                  │       19671f4aa88b82d0f64fc1 
│                       │     │                  ├ [8] : https://github.com/moby/moby/commit/ae160b4edddb72ef4b
│                       │     │                  │       d71f66b975a1a1cc434f00 
│                       │     │                  ├ [9] : https://github.com/moby/moby/commit/ae2b3666c517c96cbc
│                       │     │                  │       2adf1af5591a6b00d4ec0f 
│                       │     │                  ├ [10]: https://github.com/moby/moby/commit/cc13f952511154a286
│                       │     │                  │       6bddbb7dddebfe9e83b801 
│                       │     │                  ├ [11]: https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c
│                       │     │                  │       91697fb327dd1fb95588fb 
│                       │     │                  ├ [12]: https://github.com/moby/moby/security/advisories/GHSA-
│                       │     │                  │       v23v-6jw2-98fq 
│                       │     │                  ├ [13]: https://lists.debian.org/debian-lts-announce/2024/10/m
│                       │     │                  │       sg00009.html 
│                       │     │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2024-41110 
│                       │     │                  ├ [15]: https://security.netapp.com/advisory/ntap-20240802-0001/ 
│                       │     │                  ├ [16]: https://ubuntu.com/security/notices/USN-7161-1 
│                       │     │                  ├ [17]: https://ubuntu.com/security/notices/USN-7161-2 
│                       │     │                  ├ [18]: https://www.cve.org/CVERecord?id=CVE-2024-41110 
│                       │     │                  ├ [19]: https://www.docker.com/blog/docker-security-advisory-d
│                       │     │                  │       ocker-engine-authz-plugin 
│                       │     │                  ╰ [20]: https://www.docker.com/blog/docker-security-advisory-d
│                       │     │                          ocker-engine-authz-plugin/ 
│                       │     ├ PublishedDate   : 2024-07-24T17:15:11.053Z 
│                       │     ╰ LastModifiedDate: 2024-11-21T09:32:15.16Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2024-6104 
│                       │     ├ PkgID           : github.com/hashicorp/go-retryablehttp@v0.7.4 
│                       │     ├ PkgName         : github.com/hashicorp/go-retryablehttp 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/hashicorp/go-retryablehttp@v0.7.4 
│                       │     │                  ╰ UID : 79c3c1935c21bd6 
│                       │     ├ InstalledVersion: v0.7.4 
│                       │     ├ FixedVersion    : 0.7.7 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-6104 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : go-retryablehttp: url might write sensitive information to
│                       │     │                   log file 
│                       │     ├ Description     : go-retryablehttp prior to 0.7.7 did not sanitize urls when
│                       │     │                   writing them to its log file. This could lead to
│                       │     │                   go-retryablehttp writing sensitive HTTP basic auth
│                       │     │                   credentials to its log file. This vulnerability,
│                       │     │                   CVE-2024-6104, was fixed in go-retryablehttp 0.7.7. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-532 
│                       │     ├ VendorSeverity   ╭ alma       : 2 
│                       │     │                  ├ amazon     : 3 
│                       │     │                  ├ azure      : 2 
│                       │     │                  ├ cbl-mariner: 2 
│                       │     │                  ├ ghsa       : 2 
│                       │     │                  ├ nvd        : 2 
│                       │     │                  ├ oracle-oval: 2 
│                       │     │                  ╰ redhat     : 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 6 
│                       │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.5 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 6 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2024:9115 
│                       │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2024-6104 
│                       │     │                  ├ [2] : https://bugzilla.redhat.com/2279814 
│                       │     │                  ├ [3] : https://bugzilla.redhat.com/2292668 
│                       │     │                  ├ [4] : https://bugzilla.redhat.com/2292787 
│                       │     │                  ├ [5] : https://bugzilla.redhat.com/2294000 
│                       │     │                  ├ [6] : https://bugzilla.redhat.com/2295310 
│                       │     │                  ├ [7] : https://discuss.hashicorp.com/c/security 
│                       │     │                  ├ [8] : https://discuss.hashicorp.com/t/hcsec-2024-12-go-retry
│                       │     │                  │       ablehttp-can-leak-basic-auth-credentials-to-log-files/
│                       │     │                  │       68027 
│                       │     │                  ├ [9] : https://errata.almalinux.org/9/ALSA-2024-9115.html 
│                       │     │                  ├ [10]: https://github.com/advisories/GHSA-v6v8-xj6m-xwqh 
│                       │     │                  ├ [11]: https://github.com/hashicorp/go-retryablehttp 
│                       │     │                  ├ [12]: https://github.com/hashicorp/go-retryablehttp/commit/a
│                       │     │                  │       99f07beb3c5faaa0a283617e6eb6bcf25f5049a 
│                       │     │                  ├ [13]: https://linux.oracle.com/cve/CVE-2024-6104.html 
│                       │     │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2024-9115.html 
│                       │     │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2024-6104 
│                       │     │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2024-6104 
│                       │     ├ PublishedDate   : 2024-06-24T17:15:11.087Z 
│                       │     ╰ LastModifiedDate: 2024-11-21T09:48:58.263Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2024-45337 
│                       │     ├ PkgID           : golang.org/x/crypto@v0.24.0 
│                       │     ├ PkgName         : golang.org/x/crypto 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.24.0 
│                       │     │                  ╰ UID : 5041d33a8847de35 
│                       │     ├ InstalledVersion: v0.24.0 
│                       │     ├ FixedVersion    : 0.31.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-45337 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : golang.org/x/crypto/ssh: Misuse of
│                       │     │                   ServerConfig.PublicKeyCallback may cause authorization bypass
│                       │     │                    in golang.org/x/crypto 
│                       │     ├ Description     : Applications and libraries which misuse
│                       │     │                   connection.serverAuthenticate (via callback field
│                       │     │                   ServerConfig.PublicKeyCallback) may be susceptible to an
│                       │     │                   authorization bypass. The documentation for
│                       │     │                   ServerConfig.PublicKeyCallback says that "A call to this
│                       │     │                   function does not guarantee that the key offered is in fact
│                       │     │                   used to authenticate." Specifically, the SSH protocol allows
│                       │     │                   clients to inquire about whether a public key is acceptable
│                       │     │                   before proving control of the corresponding private key.
│                       │     │                   PublicKeyCallback may be called with multiple keys, and the
│                       │     │                   order in which the keys were provided cannot be used to infer
│                       │     │                    which key the client successfully authenticated with, if
│                       │     │                   any. Some applications, which store the key(s) passed to
│                       │     │                   PublicKeyCallback (or derived information) and make security
│                       │     │                   relevant determinations based on it once the connection is
│                       │     │                   established, may make incorrect assumptions. For example, an
│                       │     │                   attacker may send public keys A and B, and then authenticate
│                       │     │                   with A. PublicKeyCallback would be called only twice, first
│                       │     │                   with A and then with B. A vulnerable application may then
│                       │     │                   make authorization decisions based on key B for which the
│                       │     │                   attacker does not actually control the private key. Since
│                       │     │                   this API is widely misused, as a partial mitigation
│                       │     │                   golang.org/x/cry...@v0.31.0 enforces the property that, when
│                       │     │                   successfully authenticating via public key, the last key
│                       │     │                   passed to ServerConfig.PublicKeyCallback will be the key used
│                       │     │                    to authenticate the connection. PublicKeyCallback will now
│                       │     │                   be called multiple times with the same key, if necessary.
│                       │     │                   Note that the client may still not control the last key
│                       │     │                   passed to PublicKeyCallback if the connection is then
│                       │     │                   authenticated with a different method, such as
│                       │     │                   PasswordCallback, KeyboardInteractiveCallback, or
│                       │     │                   NoClientAuth. Users should be using the Extensions field of
│                       │     │                   the Permissions return value from the various authentication
│                       │     │                   callbacks to record data associated with the authentication
│                       │     │                   attempt instead of referencing external state. Once the
│                       │     │                   connection is established the state corresponding to the
│                       │     │                   successful authentication attempt can be retrieved via the
│                       │     │                   ServerConn.Permissions field. Note that some third-party
│                       │     │                   libraries misuse the Permissions type by sharing it across
│                       │     │                   authentication attempts; users of third-party libraries
│                       │     │                   should refer to the relevant projects for guidance. 
│                       │     ├ Severity        : CRITICAL 
│                       │     ├ VendorSeverity   ╭ amazon     : 3 
│                       │     │                  ├ azure      : 4 
│                       │     │                  ├ cbl-mariner: 4 
│                       │     │                  ├ ghsa       : 4 
│                       │     │                  ╰ redhat     : 3 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 9.1 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 8.2 
│                       │     ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2024/12/11/2 
│                       │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2024-45337 
│                       │     │                  ├ [2] : https://github.com/golang/crypto 
│                       │     │                  ├ [3] : https://github.com/golang/crypto/commit/b4f1988a35dee1
│                       │     │                  │       1ec3e05d6bf3e90b695fbd8909 
│                       │     │                  ├ [4] : https://go.dev/cl/635315 
│                       │     │                  ├ [5] : https://go.dev/issue/70779 
│                       │     │                  ├ [6] : https://groups.google.com/g/golang-announce/c/-nPEi39g
│                       │     │                  │       I4Q/m/cGVPJCqdAQAJ 
│                       │     │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2024-45337 
│                       │     │                  ├ [8] : https://pkg.go.dev/vuln/GO-2024-3321 
│                       │     │                  ├ [9] : https://security.netapp.com/advisory/ntap-20250131-0007 
│                       │     │                  ├ [10]: https://security.netapp.com/advisory/ntap-20250131-0007/ 
│                       │     │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2024-45337 
│                       │     ├ PublishedDate   : 2024-12-12T02:02:07.97Z 
│                       │     ╰ LastModifiedDate: 2025-02-18T21:15:22.187Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2024-45338 
│                       │     ├ PkgID           : golang.org/x/net@v0.26.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.26.0 
│                       │     │                  ╰ UID : 8c04148890da6da2 
│                       │     ├ InstalledVersion: v0.26.0 
│                       │     ├ FixedVersion    : 0.33.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-45338 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : golang.org/x/net/html: Non-linear parsing of case-insensitive
│                       │     │                    content in golang.org/x/net/html 
│                       │     ├ Description     : An attacker can craft an input to the Parse functions that
│                       │     │                   would be processed non-linearly with respect to its length,
│                       │     │                   resulting in extremely slow parsing. This could cause a
│                       │     │                   denial of service. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-1333 
│                       │     ├ VendorSeverity   ╭ amazon     : 3 
│                       │     │                  ├ azure      : 3 
│                       │     │                  ├ cbl-mariner: 3 
│                       │     │                  ├ ghsa       : 3 
│                       │     │                  ├ redhat     : 3 
│                       │     │                  ╰ ubuntu     : 2 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2024-45338 
│                       │     │                  ├ [1] : https://cs.opensource.google/go/x/net 
│                       │     │                  ├ [2] : https://github.com/golang/go/issues/70906 
│                       │     │                  ├ [3] : https://go-review.googlesource.com/c/net/+/637536 
│                       │     │                  ├ [4] : https://go.dev/cl/637536 
│                       │     │                  ├ [5] : https://go.dev/issue/70906 
│                       │     │                  ├ [6] : https://groups.google.com/g/golang-announce/c/wSCRmFnN
│                       │     │                  │       mPA/m/Lvcd0mRMAwAJ 
│                       │     │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2024-45338 
│                       │     │                  ├ [8] : https://pkg.go.dev/vuln/GO-2024-3333 
│                       │     │                  ├ [9] : https://security.netapp.com/advisory/ntap-20250221-0001/ 
│                       │     │                  ├ [10]: https://ubuntu.com/security/notices/USN-7197-1 
│                       │     │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2024-45338 
│                       │     ├ PublishedDate   : 2024-12-18T21:15:08.173Z 
│                       │     ╰ LastModifiedDate: 2025-02-21T18:15:17.717Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2025-22870 
│                       │     ├ PkgID           : golang.org/x/net@v0.26.0 
│                       │     ├ PkgName         : golang.org/x/net 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.26.0 
│                       │     │                  ╰ UID : 8c04148890da6da2 
│                       │     ├ InstalledVersion: v0.26.0 
│                       │     ├ FixedVersion    : 0.36.0 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                       │     │                  │         bd8cd23b37fd2554d3e 
│                       │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                       │     │                            980f52ffbcac00bc560 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22870 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : golang.org/x/net/http/httpproxy: golang.org/x/net/proxy: HTTP
│                       │     │                    Proxy bypass using IPv6 Zone IDs in golang.org/x/net 
│                       │     ├ Description     : Matching of hosts against proxy patterns can improperly treat
│                       │     │                    an IPv6 zone ID as a hostname component. For example, when
│                       │     │                   the NO_PROXY environment variable is set to "*.example.com",
│                       │     │                   a request to "[::1%25.example.com]:80` will incorrectly match
│                       │     │                    and not be proxied. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/
│                       │     │                           │           A:L 
│                       │     │                           ╰ V3Score : 4.4 
│                       │     ├ References       ╭ [0]: http://www.openwall.com/lists/oss-security/2025/03/07/2 
│                       │     │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2025-22870 
│                       │     │                  ├ [2]: https://go-review.googlesource.com/q/project:net 
│                       │     │                  ├ [3]: https://go.dev/cl/654697 
│                       │     │                  ├ [4]: https://go.dev/issue/71984 
│                       │     │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2025-22870 
│                       │     │                  ├ [6]: https://pkg.go.dev/vuln/GO-2025-3503 
│                       │     │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2025-22870 
│                       │     ├ PublishedDate   : 2025-03-12T19:15:38.31Z 
│                       │     ╰ LastModifiedDate: 2025-03-12T19:15:38.31Z 
│                       ╰ [6] ╭ VulnerabilityID : GHSA-xr7q-jx4m-x55m 
│                             ├ PkgID           : google.golang.org/grpc@v1.64.0 
│                             ├ PkgName         : google.golang.org/grpc 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.64.0 
│                             │                  ╰ UID : b5e6dd3f671415d3 
│                             ├ InstalledVersion: v1.64.0 
│                             ├ FixedVersion    : 1.64.1 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
│                             │                  │         bd8cd23b37fd2554d3e 
│                             │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
│                             │                            980f52ffbcac00bc560 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-xr7q-jx4m-x55m 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : Private tokens could appear in logs if context containing
│                             │                   gRPC metadata is logged in github.com/grpc/grpc-go 
│                             ├ Description     : ### Impact
│                             │                   This issue represents a potential PII concern.  If
│                             │                   applications were printing or logging a context containing
│                             │                   gRPC metadata, the affected versions will contain all the
│                             │                   metadata, which may include private information.
│                             │                   
│                             │                   ### Patches
│                             │                   The issue first appeared in 1.64.0 and is patched in 1.64.1
│                             │                   and 1.65.0
│                             │                   ### Workarounds
│                             │                   If using an affected version and upgrading is not possible,
│                             │                   ensuring you do not log or print contexts will avoid the
│                             │                   problem. 
│                             ├ Severity        : LOW 
│                             ├ VendorSeverity   ─ ghsa: 1 
│                             ╰ References       ╭ [0]: https://github.com/grpc/grpc-go 
│                                                ├ [1]: https://github.com/grpc/grpc-go/commit/ab292411ddc0f3b7
│                                                │      a7786754d1fe05264c3021eb 
│                                                ╰ [2]: https://github.com/grpc/grpc-go/security/advisories/GHS
│                                                       A-xr7q-jx4m-x55m 
╰ [6] ╭ Target         : usr/bin/promtool 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2024-35255 
                        │     ├ PkgID           : github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.5.2 
                        │     ├ PkgName         : github.com/Azure/azure-sdk-for-go/sdk/azidentity 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/azure/azure-sdk-for-go/sdk/azide
                        │     │                  │       ntity@v1.5.2 
                        │     │                  ╰ UID : 5d9a061b58d6e8c0 
                        │     ├ InstalledVersion: v1.5.2 
                        │     ├ FixedVersion    : 1.6.0 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                        │     │                  │         bd8cd23b37fd2554d3e 
                        │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                        │     │                            980f52ffbcac00bc560 
                        │     ├ SeveritySource  : ghsa 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-35255 
                        │     ├ DataSource       ╭ ID  : ghsa 
                        │     │                  ├ Name: GitHub Security Advisory Go 
                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                        │     │                          osystem%3Ago 
                        │     ├ Title           : azure-identity: Azure Identity Libraries Elevation of
                        │     │                   Privilege Vulnerability in
                        │     │                   github.com/Azure/azure-sdk-for-go/sdk/azidentity 
                        │     ├ Description     : Azure Identity Libraries and Microsoft Authentication Library
                        │     │                    Elevation of Privilege Vulnerability 
                        │     ├ Severity        : MEDIUM 
                        │     ├ CweIDs           ─ [0]: CWE-362 
                        │     ├ VendorSeverity   ╭ amazon     : 3 
                        │     │                  ├ azure      : 2 
                        │     │                  ├ cbl-mariner: 2 
                        │     │                  ├ ghsa       : 2 
                        │     │                  ╰ redhat     : 2 
                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/
                        │     │                  │        │           A:N 
                        │     │                  │        ╰ V3Score : 5.5 
                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/
                        │     │                           │           A:N 
                        │     │                           ╰ V3Score : 5.5 
                        │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2024-35255 
                        │     │                  ├ [1] : https://github.com/Azure/azure-sdk-for-go/commit/50774
                        │     │                  │       cd9709905523136fb05e8c85a50e8984499 
                        │     │                  ├ [2] : https://github.com/Azure/azure-sdk-for-java/commit/5bf
                        │     │                  │       020d6ea056de40e2738e3647a4e06f902c18d 
                        │     │                  ├ [3] : https://github.com/Azure/azure-sdk-for-js/commit/c6aa7
                        │     │                  │       5d312ae463e744163cedfd8fc480cc8d492 
                        │     │                  ├ [4] : https://github.com/Azure/azure-sdk-for-net/commit/9279
                        │     │                  │       a4f38bf69b457cfb9b354f210e0a540a5c53 
                        │     │                  ├ [5] : https://github.com/Azure/azure-sdk-for-python/commit/c
                        │     │                  │       b065acd7d0f957327dc4f02d1646d4e51a94178 
                        │     │                  ├ [6] : https://github.com/AzureAD/microsoft-authentication-li
                        │     │                  │       brary-for-dotnet/issues/4806#issuecomment-2178960340 
                        │     │                  ├ [7] : https://github.com/advisories/GHSA-m5vv-6r4h-3vj9 
                        │     │                  ├ [8] : https://msrc.microsoft.com/update-guide/vulnerability/
                        │     │                  │       CVE-2024-35255 
                        │     │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2024-35255 
                        │     │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2024-35255 
                        │     ├ PublishedDate   : 2024-06-11T17:16:03.55Z 
                        │     ╰ LastModifiedDate: 2024-11-21T09:20:01.923Z 
                        ├ [1] ╭ VulnerabilityID : CVE-2024-41110 
                        │     ├ PkgID           : github.com/docker/docker@v26.1.3+incompatible 
                        │     ├ PkgName         : github.com/docker/docker 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v26.1.3%2Bincompat
                        │     │                  │       ible 
                        │     │                  ╰ UID : e66cf037ad7083b6 
                        │     ├ InstalledVersion: v26.1.3+incompatible 
                        │     ├ FixedVersion    : 23.0.15, 26.1.5, 27.1.1, 25.0.6 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                        │     │                  │         bd8cd23b37fd2554d3e 
                        │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                        │     │                            980f52ffbcac00bc560 
                        │     ├ SeveritySource  : ghsa 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-41110 
                        │     ├ DataSource       ╭ ID  : ghsa 
                        │     │                  ├ Name: GitHub Security Advisory Go 
                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                        │     │                          osystem%3Ago 
                        │     ├ Title           : moby: Authz zero length regression 
                        │     ├ Description     : Moby is an open-source project created by Docker for software
                        │     │                    containerization. A security vulnerability has been detected
                        │     │                    in certain versions of Docker Engine, which could allow an
                        │     │                   attacker to bypass authorization plugins (AuthZ) under
                        │     │                   specific circumstances. The base likelihood of this being
                        │     │                   exploited is low.
                        │     │                   
                        │     │                   Using a specially-crafted API request, an Engine API client
                        │     │                   could make the daemon forward the request or response to an
                        │     │                   authorization plugin without the body. In certain
                        │     │                   circumstances, the authorization plugin may allow a request
                        │     │                   which it would have otherwise denied if the body had been
                        │     │                   forwarded to it.
                        │     │                   A security issue was discovered In 2018, where an attacker
                        │     │                   could bypass AuthZ plugins using a specially crafted API
                        │     │                   request. This could lead to unauthorized actions, including
                        │     │                   privilege escalation. Although this issue was fixed in Docker
                        │     │                    Engine v18.09.1 in January 2019, the fix was not carried
                        │     │                   forward to later major versions, resulting in a regression.
                        │     │                   Anyone who depends on authorization plugins that introspect
                        │     │                   the request and/or response body to make access control
                        │     │                   decisions is potentially impacted.
                        │     │                   Docker EE v19.03.x and all versions of Mirantis Container
                        │     │                   Runtime are not vulnerable.
                        │     │                   docker-ce v27.1.1 containes patches to fix the vulnerability.
                        │     │                    Patches have also been merged into the master, 19.03, 20.0,
                        │     │                   23.0, 24.0, 25.0, 26.0, and 26.1 release branches. If one is
                        │     │                   unable to upgrade immediately, avoid using AuthZ plugins
                        │     │                   and/or restrict access to the Docker API to trusted parties,
                        │     │                   following the principle of least privilege. 
                        │     ├ Severity        : CRITICAL 
                        │     ├ CweIDs           ╭ [0]: CWE-187 
                        │     │                  ├ [1]: CWE-444 
                        │     │                  ╰ [2]: CWE-863 
                        │     ├ VendorSeverity   ╭ amazon     : 3 
                        │     │                  ├ azure      : 4 
                        │     │                  ├ cbl-mariner: 4 
                        │     │                  ├ ghsa       : 4 
                        │     │                  ├ redhat     : 4 
                        │     │                  ╰ ubuntu     : 3 
                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/
                        │     │                  │        │           A:H 
                        │     │                  │        ╰ V3Score : 10 
                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/
                        │     │                           │           A:H 
                        │     │                           ╰ V3Score : 9.9 
                        │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2024-41110 
                        │     │                  ├ [1] : https://github.com/moby/moby 
                        │     │                  ├ [2] : https://github.com/moby/moby/commit/411e817ddf710ff8e0
                        │     │                  │       8fa193da80cb78af708191 
                        │     │                  ├ [3] : https://github.com/moby/moby/commit/42f40b1d6dd7562342
                        │     │                  │       f832b9cd2adf9e668eeb76 
                        │     │                  ├ [4] : https://github.com/moby/moby/commit/65cc597cea28cdc25b
                        │     │                  │       ea3b8a86384b4251872919 
                        │     │                  ├ [5] : https://github.com/moby/moby/commit/852759a7df454cbf88
                        │     │                  │       db4e954c919becd48faa9b 
                        │     │                  ├ [6] : https://github.com/moby/moby/commit/a31260625655cff9ae
                        │     │                  │       226b51757915e275e304b0 
                        │     │                  ├ [7] : https://github.com/moby/moby/commit/a79fabbfe84117696a
                        │     │                  │       19671f4aa88b82d0f64fc1 
                        │     │                  ├ [8] : https://github.com/moby/moby/commit/ae160b4edddb72ef4b
                        │     │                  │       d71f66b975a1a1cc434f00 
                        │     │                  ├ [9] : https://github.com/moby/moby/commit/ae2b3666c517c96cbc
                        │     │                  │       2adf1af5591a6b00d4ec0f 
                        │     │                  ├ [10]: https://github.com/moby/moby/commit/cc13f952511154a286
                        │     │                  │       6bddbb7dddebfe9e83b801 
                        │     │                  ├ [11]: https://github.com/moby/moby/commit/fc274cd2ff4cf3b48c
                        │     │                  │       91697fb327dd1fb95588fb 
                        │     │                  ├ [12]: https://github.com/moby/moby/security/advisories/GHSA-
                        │     │                  │       v23v-6jw2-98fq 
                        │     │                  ├ [13]: https://lists.debian.org/debian-lts-announce/2024/10/m
                        │     │                  │       sg00009.html 
                        │     │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2024-41110 
                        │     │                  ├ [15]: https://security.netapp.com/advisory/ntap-20240802-0001/ 
                        │     │                  ├ [16]: https://ubuntu.com/security/notices/USN-7161-1 
                        │     │                  ├ [17]: https://ubuntu.com/security/notices/USN-7161-2 
                        │     │                  ├ [18]: https://www.cve.org/CVERecord?id=CVE-2024-41110 
                        │     │                  ├ [19]: https://www.docker.com/blog/docker-security-advisory-d
                        │     │                  │       ocker-engine-authz-plugin 
                        │     │                  ╰ [20]: https://www.docker.com/blog/docker-security-advisory-d
                        │     │                          ocker-engine-authz-plugin/ 
                        │     ├ PublishedDate   : 2024-07-24T17:15:11.053Z 
                        │     ╰ LastModifiedDate: 2024-11-21T09:32:15.16Z 
                        ├ [2] ╭ VulnerabilityID : CVE-2024-6104 
                        │     ├ PkgID           : github.com/hashicorp/go-retryablehttp@v0.7.4 
                        │     ├ PkgName         : github.com/hashicorp/go-retryablehttp 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/hashicorp/go-retryablehttp@v0.7.4 
                        │     │                  ╰ UID : 85fbf89b64863e5a 
                        │     ├ InstalledVersion: v0.7.4 
                        │     ├ FixedVersion    : 0.7.7 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                        │     │                  │         bd8cd23b37fd2554d3e 
                        │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                        │     │                            980f52ffbcac00bc560 
                        │     ├ SeveritySource  : ghsa 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-6104 
                        │     ├ DataSource       ╭ ID  : ghsa 
                        │     │                  ├ Name: GitHub Security Advisory Go 
                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                        │     │                          osystem%3Ago 
                        │     ├ Title           : go-retryablehttp: url might write sensitive information to
                        │     │                   log file 
                        │     ├ Description     : go-retryablehttp prior to 0.7.7 did not sanitize urls when
                        │     │                   writing them to its log file. This could lead to
                        │     │                   go-retryablehttp writing sensitive HTTP basic auth
                        │     │                   credentials to its log file. This vulnerability,
                        │     │                   CVE-2024-6104, was fixed in go-retryablehttp 0.7.7. 
                        │     ├ Severity        : MEDIUM 
                        │     ├ CweIDs           ─ [0]: CWE-532 
                        │     ├ VendorSeverity   ╭ alma       : 2 
                        │     │                  ├ amazon     : 3 
                        │     │                  ├ azure      : 2 
                        │     │                  ├ cbl-mariner: 2 
                        │     │                  ├ ghsa       : 2 
                        │     │                  ├ nvd        : 2 
                        │     │                  ├ oracle-oval: 2 
                        │     │                  ╰ redhat     : 2 
                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/
                        │     │                  │        │           A:N 
                        │     │                  │        ╰ V3Score : 6 
                        │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/
                        │     │                  │        │           A:N 
                        │     │                  │        ╰ V3Score : 5.5 
                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:N/
                        │     │                           │           A:N 
                        │     │                           ╰ V3Score : 6 
                        │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2024:9115 
                        │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2024-6104 
                        │     │                  ├ [2] : https://bugzilla.redhat.com/2279814 
                        │     │                  ├ [3] : https://bugzilla.redhat.com/2292668 
                        │     │                  ├ [4] : https://bugzilla.redhat.com/2292787 
                        │     │                  ├ [5] : https://bugzilla.redhat.com/2294000 
                        │     │                  ├ [6] : https://bugzilla.redhat.com/2295310 
                        │     │                  ├ [7] : https://discuss.hashicorp.com/c/security 
                        │     │                  ├ [8] : https://discuss.hashicorp.com/t/hcsec-2024-12-go-retry
                        │     │                  │       ablehttp-can-leak-basic-auth-credentials-to-log-files/
                        │     │                  │       68027 
                        │     │                  ├ [9] : https://errata.almalinux.org/9/ALSA-2024-9115.html 
                        │     │                  ├ [10]: https://github.com/advisories/GHSA-v6v8-xj6m-xwqh 
                        │     │                  ├ [11]: https://github.com/hashicorp/go-retryablehttp 
                        │     │                  ├ [12]: https://github.com/hashicorp/go-retryablehttp/commit/a
                        │     │                  │       99f07beb3c5faaa0a283617e6eb6bcf25f5049a 
                        │     │                  ├ [13]: https://linux.oracle.com/cve/CVE-2024-6104.html 
                        │     │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2024-9115.html 
                        │     │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2024-6104 
                        │     │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2024-6104 
                        │     ├ PublishedDate   : 2024-06-24T17:15:11.087Z 
                        │     ╰ LastModifiedDate: 2024-11-21T09:48:58.263Z 
                        ├ [3] ╭ VulnerabilityID : CVE-2024-45337 
                        │     ├ PkgID           : golang.org/x/crypto@v0.24.0 
                        │     ├ PkgName         : golang.org/x/crypto 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.24.0 
                        │     │                  ╰ UID : b5e00da11cee68d9 
                        │     ├ InstalledVersion: v0.24.0 
                        │     ├ FixedVersion    : 0.31.0 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                        │     │                  │         bd8cd23b37fd2554d3e 
                        │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                        │     │                            980f52ffbcac00bc560 
                        │     ├ SeveritySource  : ghsa 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-45337 
                        │     ├ DataSource       ╭ ID  : ghsa 
                        │     │                  ├ Name: GitHub Security Advisory Go 
                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                        │     │                          osystem%3Ago 
                        │     ├ Title           : golang.org/x/crypto/ssh: Misuse of
                        │     │                   ServerConfig.PublicKeyCallback may cause authorization bypass
                        │     │                    in golang.org/x/crypto 
                        │     ├ Description     : Applications and libraries which misuse
                        │     │                   connection.serverAuthenticate (via callback field
                        │     │                   ServerConfig.PublicKeyCallback) may be susceptible to an
                        │     │                   authorization bypass. The documentation for
                        │     │                   ServerConfig.PublicKeyCallback says that "A call to this
                        │     │                   function does not guarantee that the key offered is in fact
                        │     │                   used to authenticate." Specifically, the SSH protocol allows
                        │     │                   clients to inquire about whether a public key is acceptable
                        │     │                   before proving control of the corresponding private key.
                        │     │                   PublicKeyCallback may be called with multiple keys, and the
                        │     │                   order in which the keys were provided cannot be used to infer
                        │     │                    which key the client successfully authenticated with, if
                        │     │                   any. Some applications, which store the key(s) passed to
                        │     │                   PublicKeyCallback (or derived information) and make security
                        │     │                   relevant determinations based on it once the connection is
                        │     │                   established, may make incorrect assumptions. For example, an
                        │     │                   attacker may send public keys A and B, and then authenticate
                        │     │                   with A. PublicKeyCallback would be called only twice, first
                        │     │                   with A and then with B. A vulnerable application may then
                        │     │                   make authorization decisions based on key B for which the
                        │     │                   attacker does not actually control the private key. Since
                        │     │                   this API is widely misused, as a partial mitigation
                        │     │                   golang.org/x/cry...@v0.31.0 enforces the property that, when
                        │     │                   successfully authenticating via public key, the last key
                        │     │                   passed to ServerConfig.PublicKeyCallback will be the key used
                        │     │                    to authenticate the connection. PublicKeyCallback will now
                        │     │                   be called multiple times with the same key, if necessary.
                        │     │                   Note that the client may still not control the last key
                        │     │                   passed to PublicKeyCallback if the connection is then
                        │     │                   authenticated with a different method, such as
                        │     │                   PasswordCallback, KeyboardInteractiveCallback, or
                        │     │                   NoClientAuth. Users should be using the Extensions field of
                        │     │                   the Permissions return value from the various authentication
                        │     │                   callbacks to record data associated with the authentication
                        │     │                   attempt instead of referencing external state. Once the
                        │     │                   connection is established the state corresponding to the
                        │     │                   successful authentication attempt can be retrieved via the
                        │     │                   ServerConn.Permissions field. Note that some third-party
                        │     │                   libraries misuse the Permissions type by sharing it across
                        │     │                   authentication attempts; users of third-party libraries
                        │     │                   should refer to the relevant projects for guidance. 
                        │     ├ Severity        : CRITICAL 
                        │     ├ VendorSeverity   ╭ amazon     : 3 
                        │     │                  ├ azure      : 4 
                        │     │                  ├ cbl-mariner: 4 
                        │     │                  ├ ghsa       : 4 
                        │     │                  ╰ redhat     : 3 
                        │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/
                        │     │                  │        │           A:N 
                        │     │                  │        ╰ V3Score : 9.1 
                        │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/
                        │     │                           │           A:N 
                        │     │                           ╰ V3Score : 8.2 
                        │     ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2024/12/11/2 
                        │     │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2024-45337 
                        │     │                  ├ [2] : https://github.com/golang/crypto 
                        │     │                  ├ [3] : https://github.com/golang/crypto/commit/b4f1988a35dee1
                        │     │                  │       1ec3e05d6bf3e90b695fbd8909 
                        │     │                  ├ [4] : https://go.dev/cl/635315 
                        │     │                  ├ [5] : https://go.dev/issue/70779 
                        │     │                  ├ [6] : https://groups.google.com/g/golang-announce/c/-nPEi39g
                        │     │                  │       I4Q/m/cGVPJCqdAQAJ 
                        │     │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2024-45337 
                        │     │                  ├ [8] : https://pkg.go.dev/vuln/GO-2024-3321 
                        │     │                  ├ [9] : https://security.netapp.com/advisory/ntap-20250131-0007 
                        │     │                  ├ [10]: https://security.netapp.com/advisory/ntap-20250131-0007/ 
                        │     │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2024-45337 
                        │     ├ PublishedDate   : 2024-12-12T02:02:07.97Z 
                        │     ╰ LastModifiedDate: 2025-02-18T21:15:22.187Z 
                        ├ [4] ╭ VulnerabilityID : CVE-2024-45338 
                        │     ├ PkgID           : golang.org/x/net@v0.26.0 
                        │     ├ PkgName         : golang.org/x/net 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.26.0 
                        │     │                  ╰ UID : 4075f6667d6d269e 
                        │     ├ InstalledVersion: v0.26.0 
                        │     ├ FixedVersion    : 0.33.0 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                        │     │                  │         bd8cd23b37fd2554d3e 
                        │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                        │     │                            980f52ffbcac00bc560 
                        │     ├ SeveritySource  : ghsa 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-45338 
                        │     ├ DataSource       ╭ ID  : ghsa 
                        │     │                  ├ Name: GitHub Security Advisory Go 
                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                        │     │                          osystem%3Ago 
                        │     ├ Title           : golang.org/x/net/html: Non-linear parsing of case-insensitive
                        │     │                    content in golang.org/x/net/html 
                        │     ├ Description     : An attacker can craft an input to the Parse functions that
                        │     │                   would be processed non-linearly with respect to its length,
                        │     │                   resulting in extremely slow parsing. This could cause a
                        │     │                   denial of service. 
                        │     ├ Severity        : HIGH 
                        │     ├ CweIDs           ─ [0]: CWE-1333 
                        │     ├ VendorSeverity   ╭ amazon     : 3 
                        │     │                  ├ azure      : 3 
                        │     │                  ├ cbl-mariner: 3 
                        │     │                  ├ ghsa       : 3 
                        │     │                  ├ redhat     : 3 
                        │     │                  ╰ ubuntu     : 2 
                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/
                        │     │                           │           A:H 
                        │     │                           ╰ V3Score : 7.5 
                        │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2024-45338 
                        │     │                  ├ [1] : https://cs.opensource.google/go/x/net 
                        │     │                  ├ [2] : https://github.com/golang/go/issues/70906 
                        │     │                  ├ [3] : https://go-review.googlesource.com/c/net/+/637536 
                        │     │                  ├ [4] : https://go.dev/cl/637536 
                        │     │                  ├ [5] : https://go.dev/issue/70906 
                        │     │                  ├ [6] : https://groups.google.com/g/golang-announce/c/wSCRmFnN
                        │     │                  │       mPA/m/Lvcd0mRMAwAJ 
                        │     │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2024-45338 
                        │     │                  ├ [8] : https://pkg.go.dev/vuln/GO-2024-3333 
                        │     │                  ├ [9] : https://security.netapp.com/advisory/ntap-20250221-0001/ 
                        │     │                  ├ [10]: https://ubuntu.com/security/notices/USN-7197-1 
                        │     │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2024-45338 
                        │     ├ PublishedDate   : 2024-12-18T21:15:08.173Z 
                        │     ╰ LastModifiedDate: 2025-02-21T18:15:17.717Z 
                        ├ [5] ╭ VulnerabilityID : CVE-2025-22870 
                        │     ├ PkgID           : golang.org/x/net@v0.26.0 
                        │     ├ PkgName         : golang.org/x/net 
                        │     ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.26.0 
                        │     │                  ╰ UID : 4075f6667d6d269e 
                        │     ├ InstalledVersion: v0.26.0 
                        │     ├ FixedVersion    : 0.36.0 
                        │     ├ Status          : fixed 
                        │     ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                        │     │                  │         bd8cd23b37fd2554d3e 
                        │     │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                        │     │                            980f52ffbcac00bc560 
                        │     ├ SeveritySource  : ghsa 
                        │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-22870 
                        │     ├ DataSource       ╭ ID  : ghsa 
                        │     │                  ├ Name: GitHub Security Advisory Go 
                        │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                        │     │                          osystem%3Ago 
                        │     ├ Title           : golang.org/x/net/http/httpproxy: golang.org/x/net/proxy: HTTP
                        │     │                    Proxy bypass using IPv6 Zone IDs in golang.org/x/net 
                        │     ├ Description     : Matching of hosts against proxy patterns can improperly treat
                        │     │                    an IPv6 zone ID as a hostname component. For example, when
                        │     │                   the NO_PROXY environment variable is set to "*.example.com",
                        │     │                   a request to "[::1%25.example.com]:80` will incorrectly match
                        │     │                    and not be proxied. 
                        │     ├ Severity        : MEDIUM 
                        │     ├ VendorSeverity   ╭ ghsa  : 2 
                        │     │                  ╰ redhat: 2 
                        │     ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/
                        │     │                           │           A:L 
                        │     │                           ╰ V3Score : 4.4 
                        │     ├ References       ╭ [0]: http://www.openwall.com/lists/oss-security/2025/03/07/2 
                        │     │                  ├ [1]: https://access.redhat.com/security/cve/CVE-2025-22870 
                        │     │                  ├ [2]: https://go-review.googlesource.com/q/project:net 
                        │     │                  ├ [3]: https://go.dev/cl/654697 
                        │     │                  ├ [4]: https://go.dev/issue/71984 
                        │     │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2025-22870 
                        │     │                  ├ [6]: https://pkg.go.dev/vuln/GO-2025-3503 
                        │     │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2025-22870 
                        │     ├ PublishedDate   : 2025-03-12T19:15:38.31Z 
                        │     ╰ LastModifiedDate: 2025-03-12T19:15:38.31Z 
                        ╰ [6] ╭ VulnerabilityID : GHSA-xr7q-jx4m-x55m 
                              ├ PkgID           : google.golang.org/grpc@v1.64.0 
                              ├ PkgName         : google.golang.org/grpc 
                              ├ PkgIdentifier    ╭ PURL: pkg:golang/google.golang.org/grpc@v1.64.0 
                              │                  ╰ UID : 6c7f57c93d4ea9eb 
                              ├ InstalledVersion: v1.64.0 
                              ├ FixedVersion    : 1.64.1 
                              ├ Status          : fixed 
                              ├ Layer            ╭ Digest: sha256:5da83a40302b487c53b5af8a664663f6d0d4222bb4f32
                              │                  │         bd8cd23b37fd2554d3e 
                              │                  ╰ DiffID: sha256:23142c91806b28132c5f9321c213d021f5033e8cf7e50
                              │                            980f52ffbcac00bc560 
                              ├ SeveritySource  : ghsa 
                              ├ PrimaryURL      : https://github.com/advisories/GHSA-xr7q-jx4m-x55m 
                              ├ DataSource       ╭ ID  : ghsa 
                              │                  ├ Name: GitHub Security Advisory Go 
                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
                              │                          osystem%3Ago 
                              ├ Title           : Private tokens could appear in logs if context containing
                              │                   gRPC metadata is logged in github.com/grpc/grpc-go 
                              ├ Description     : ### Impact
                              │                   This issue represents a potential PII concern.  If
                              │                   applications were printing or logging a context containing
                              │                   gRPC metadata, the affected versions will contain all the
                              │                   metadata, which may include private information.
                              │                   
                              │                   ### Patches
                              │                   The issue first appeared in 1.64.0 and is patched in 1.64.1
                              │                   and 1.65.0
                              │                   ### Workarounds
                              │                   If using an affected version and upgrading is not possible,
                              │                   ensuring you do not log or print contexts will avoid the
                              │                   problem. 
                              ├ Severity        : LOW 
                              ├ VendorSeverity   ─ ghsa: 1 
                              ╰ References       ╭ [0]: https://github.com/grpc/grpc-go 
                                                 ├ [1]: https://github.com/grpc/grpc-go/commit/ab292411ddc0f3b7
                                                 │      a7786754d1fe05264c3021eb 
                                                 ╰ [2]: https://github.com/grpc/grpc-go/security/advisories/GHS
                                                        A-xr7q-jx4m-x55m 
````

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
├ [4] ╭ Target: usr/bin/prometheus 
│     ├ Class : lang-pkgs 
│     ╰ Type  : gobinary 
├ [5] ╭ Target: usr/bin/promtool 
│     ├ Class : lang-pkgs 
│     ╰ Type  : gobinary 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2025-48371 
│                             ├ PkgID           : github.com/openfga/openfga@v1.8.12 
│                             ├ PkgName         : github.com/openfga/openfga 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.8.12 
│                             │                  ╰ UID : 3d13096c276c89b0 
│                             ├ InstalledVersion: v1.8.12 
│                             ├ FixedVersion    : 1.8.13 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:5cfad64fef91b46b7efc5115fb7ed3ebed9f8f3e085a2
│                             │                  │         b3d363951b18cec8018 
│                             │                  ╰ DiffID: sha256:fd48fb93c6179d5f8866cc2b2286e5f36a40b6806ff0d
│                             │                            a38377ac2eb9090ad0b 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-48371 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : OpenFGA Authorization Bypass 
│                             ├ Description     : OpenFGA is an authorization/permission engine. OpenFGA
│                             │                   versions 1.8.0 through 1.8.12 (corresponding to Helm chart
│                             │                   openfga-0.2.16 through openfga-0.2.30 and docker 1.8.0
│                             │                   through 1.8.12) are vulnerable to authorization bypass when
│                             │                   certain Check and ListObject calls are executed. Users are
│                             │                   affected under four specific conditions: First, calling Check
│                             │                    API or ListObjects with an authorization model that has a
│                             │                   relationship directly assignable by both type bound public
│                             │                   access and userset; second, there are check or list object
│                             │                   queries with contextual tuples for the relationship that can
│                             │                   be directly assignable by both type bound public access and
│                             │                   userset; third, those contextual tuples’s user field is an
│                             │                   userset; and finally, type bound public access tuples are not
│                             │                    assigned to the relationship. Users should upgrade to
│                             │                   version 1.8.13 to receive a patch. The upgrade is backwards
│                             │                   compatible. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-285 
│                             ├ VendorSeverity   ─ ghsa: 2 
│                             ├ References       ╭ [0]: https://github.com/openfga/openfga 
│                             │                  ├ [1]: https://github.com/openfga/openfga/commit/e5960d4eba92b
│                             │                  │      723de8ff3a5346a07f50c1379ca 
│                             │                  ├ [2]: https://github.com/openfga/openfga/security/advisories/
│                             │                  │      GHSA-c72g-53hw-82q7 
│                             │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2025-48371 
│                             │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2025-3707 
│                             ├ PublishedDate   : 2025-05-22T23:15:19.23Z 
│                             ╰ LastModifiedDate: 2025-05-23T15:54:42.643Z 
├ [7] ╭ Target: usr/share/grafana/bin/grafana-cli 
│     ├ Class : lang-pkgs 
│     ╰ Type  : gobinary 
╰ [8] ╭ Target: usr/share/grafana/bin/grafana-server 
      ├ Class : lang-pkgs 
      ╰ Type  : gobinary 
````

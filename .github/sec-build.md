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
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-32285 
│                       │      ├ VendorIDs        ─ [0]: GHSA-6g7g-w4f8-9c9x 
│                       │      ├ PkgID           : github.com/buger/jsonparser@v1.1.1 
│                       │      ├ PkgName         : github.com/buger/jsonparser 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/buger/jsonparser@v1.1.1 
│                       │      │                  ╰ UID : b50dbcea97aa419d 
│                       │      ├ InstalledVersion: v1.1.1 
│                       │      ├ FixedVersion    : 1.1.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32285 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:2330069c948de5fe31d675e4955a5238439ca4d067f37fe1cedcd
│                       │      │                   042685b41e7 
│                       │      ├ Title           : github.com/buger/jsonparser: github.com/buger/jsonparser:
│                       │      │                   Denial of Service via malformed JSON input 
│                       │      ├ Description     : The Delete function fails to properly validate offsets when
│                       │      │                   processing malformed JSON input. This can lead to a negative
│                       │      │                    slice index and a runtime panic, allowing a denial of
│                       │      │                   service attack. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-129 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ ghsa  : 3 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-32285 
│                       │      │                  ├ [1] : https://github.com/buger/jsonparser 
│                       │      │                  ├ [2] : https://github.com/buger/jsonparser/commit/a69e7e01cd
│                       │      │                  │       4ad67bdfd3ac2c080b9212af16f4b0 
│                       │      │                  ├ [3] : https://github.com/buger/jsonparser/issues/275 
│                       │      │                  ├ [4] : https://github.com/buger/jsonparser/pull/276 
│                       │      │                  ├ [5] : https://github.com/buger/jsonparser/releases/tag/v1.1.2 
│                       │      │                  ├ [6] : https://github.com/golang/vulndb/issues/4514 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2026-32285 
│                       │      │                  ├ [8] : https://pkg.go.dev/vuln/GO-2026-4514 
│                       │      │                  ├ [9] : https://securityinfinity.com/research/buger-jsonparse
│                       │      │                  │       r-negative-slice-panic-dos-2026 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2026-32285 
│                       │      ├ PublishedDate   : 2026-03-26T20:16:12.197Z 
│                       │      ╰ LastModifiedDate: 2026-04-21T15:42:07.52Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-34040 
│                       │      ├ VendorIDs        ─ [0]: GHSA-x744-4wpc-v9h2 
│                       │      ├ PkgID           : github.com/docker/docker@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/docker/docker 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v28.5.2%2Bincompa
│                       │      │                  │       tible 
│                       │      │                  ╰ UID : b9fad9eea692e510 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ FixedVersion    : 29.3.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-34040 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:746508e9601584fbd2966c2afe0eb37a883b7df966c1669feb911
│                       │      │                   8cf9cf129bf 
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
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-33997 
│                       │      ├ VendorIDs        ─ [0]: GHSA-pxq6-2prw-chj9 
│                       │      ├ PkgID           : github.com/docker/docker@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/docker/docker 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v28.5.2%2Bincompa
│                       │      │                  │       tible 
│                       │      │                  ╰ UID : b9fad9eea692e510 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ FixedVersion    : 29.3.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33997 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:fe3a58ab762f450d1d4ae21e3680c5ed86f2803588248ed5cb7b0
│                       │      │                   0b4068576a4 
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
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-39882 
│                       │      ├ VendorIDs        ─ [0]: GHSA-w8rr-5gcm-pp58 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceh
│                       │      │                   ttp@v1.42.0 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptraceh
│                       │      │                   ttp 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/exporters/otlp/ot
│                       │      │                  │       lptrace/otlptracehttp@v1.42.0 
│                       │      │                  ╰ UID : 9fe3c1fba6626f73 
│                       │      ├ InstalledVersion: v1.42.0 
│                       │      ├ FixedVersion    : 1.43.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:fc72a36d5a5155d0d0d41545ab6adcc3723ab05e35e8bbf7540e6
│                       │      │                   d593b861824 
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
│                       │      ├ VendorSeverity   ╭ amazon: 2 
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
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39883 
│                       │      ├ VendorIDs        ─ [0]: GHSA-hfvc-g4fc-pqhx 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.42.0 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.42.0 
│                       │      │                  ╰ UID : 7bede0c3d74d690f 
│                       │      ├ InstalledVersion: v1.42.0 
│                       │      ├ FixedVersion    : 1.43.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:9ce1dca058f5a6922c0836c17ed96f2a9d5eeb05467b36eb9a5d7
│                       │      │                   c3b90a628ad 
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
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-33811 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4981 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:976a1b1a93fbcdb7cb86ad45d9eaf0b9e98e42f403af6b29dc911
│                       │      │                   e37ed8d7e07 
│                       │      ├ Title           : When using LookupCNAME with the cgo DNS resolver, a very
│                       │      │                   long CNAME re ... 
│                       │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
│                       │      │                   long CNAME response can trigger a double-free of C memory
│                       │      │                   and a crash. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-415 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ nvd    : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/767860 
│                       │      │                  ├ [1]: https://go.dev/issue/78803 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4981 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
│                       │      ╰ LastModifiedDate: 2026-05-12T20:23:02.333Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-33814 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4918 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5217d88ffbd1b3ea5e71e01d80030fad798535263a008ef16891d
│                       │      │                   5f2bac7bc11 
│                       │      ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │      │                    an infini ... 
│                       │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │      │                    an infinite loop of writing CONTINUATION frames if it
│                       │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-835 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ nvd    : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/761581 
│                       │      │                  ├ [1]: https://go.dev/cl/761640 
│                       │      │                  ├ [2]: https://go.dev/issue/78476 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
│                       │      │                  ╰ [5]: https://pkg.go.dev/vuln/GO-2026-4918 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T14:41:59.52Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-39820 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4986 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:492ee84b275c4ade60a3c6f9f9ec7c438cb94d892b7dec740b779
│                       │      │                   52f2d908c5d 
│                       │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │      │                    and Parse ... 
│                       │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │      │                    and ParseDate were able to trigger excessive CPU exhaustion
│                       │      │                    and memory allocations. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
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
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-39836 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4971 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b89096b021429b27ab0efa816f7ecb3e0dad1ca88b748881cbb5f
│                       │      │                   13534f498ff 
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
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-42499 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4977 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:9f4a75e94deb4a3bf0d17a6c56d8a55a3d22c32bbf3e9c4a2dca7
│                       │      │                   7252cf67baf 
│                       │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
│                       │      │                   when parsing ... 
│                       │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
│                       │      │                   when parsing an email address according to RFC 5322. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ VendorSeverity   ─ bitnami: 3 
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
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-39823 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4982 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:22e5e467fe2d059aec7aefbcc8b70083d39bcbfae1cb1bb6c76fc
│                       │      │                   2a2faaaf20f 
│                       │      ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │      │                   correctly  ... 
│                       │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │      │                   correctly escaped inside of a <meta> tag's <content>
│                       │      │                   attribute. If the URL content were to insert ASCII
│                       │      │                   whitespaces around the '=' rune inside of the <content>
│                       │      │                   attribute, the escaper would fail to similarly escape it,
│                       │      │                   leading to XSS. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ─ bitnami: 2 
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
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-39825 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4976 
│                       │      ├ PkgID           : stdlib@v1.26.2 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │      │                  ╰ UID : d663b72caca040b6 
│                       │      ├ InstalledVersion: v1.26.2 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4cec4c54ec75215c7f72fd5c46fb4fc881000e4efeea1c4daa981
│                       │      │                   d8d08ef8269 
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
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ bitnami: 2 
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
│                       ╰ [12] ╭ VulnerabilityID : CVE-2026-39826 
│                              ├ VendorIDs        ─ [0]: GO-2026-4980 
│                              ├ PkgID           : stdlib@v1.26.2 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                              │                  ╰ UID : d663b72caca040b6 
│                              ├ InstalledVersion: v1.26.2 
│                              ├ FixedVersion    : 1.25.10, 1.26.3 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                              │                  │         e604d470cc284fe84f9a 
│                              │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                              │                            c9a6ba0df01bfc18beca 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:92a277a16289653e9d650ce310fa8f80b4796f91206174aee9262
│                              │                   99ff0dd2f1a 
│                              ├ Title           : If a trusted template author were to write a <script> tag
│                              │                   containing a ... 
│                              ├ Description     : If a trusted template author were to write a <script> tag
│                              │                   containing an empty 'type' attribute or a 'type' attribute
│                              │                   with an ASCII whitespace, the execution of the template
│                              │                   would incorrectly escape any data passed into the <script>
│                              │                   block. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs           ─ [0]: CWE-116 
│                              ├ VendorSeverity   ─ bitnami: 2 
│                              ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 6.1 
│                              ├ References       ╭ [0]: https://go.dev/cl/771180 
│                              │                  ├ [1]: https://go.dev/issue/78981 
│                              │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                              │                  │      47M 
│                              │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
│                              │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4980 
│                              ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
│                              ╰ LastModifiedDate: 2026-05-13T16:59:07.48Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-34040 
│                       │     ├ VendorIDs        ─ [0]: GHSA-x744-4wpc-v9h2 
│                       │     ├ PkgID           : github.com/docker/docker@v28.5.2+incompatible 
│                       │     ├ PkgName         : github.com/docker/docker 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v28.5.2%2Bincompat
│                       │     │                  │       ible 
│                       │     │                  ╰ UID : 7900223948e2f444 
│                       │     ├ InstalledVersion: v28.5.2+incompatible 
│                       │     ├ FixedVersion    : 29.3.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-34040 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:08fb87064b7385829b189deab6d210f453ff1c28fc543869280843
│                       │     │                   f066e1d982 
│                       │     ├ Title           : Moby: Moby: Authorization bypass vulnerability 
│                       │     ├ Description     : Moby is an open source container framework. Prior to version
│                       │     │                   29.3.1, a security vulnerability has been detected that
│                       │     │                   allows attackers to bypass authorization plugins (AuthZ).
│                       │     │                   This issue has been patched in version 29.3.1. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-288 
│                       │     ├ VendorSeverity   ╭ amazon: 3 
│                       │     │                  ├ ghsa  : 3 
│                       │     │                  ├ nvd   : 3 
│                       │     │                  ├ photon: 3 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                  │        │           A:H 
│                       │     │                  │        ╰ V3Score : 8.8 
│                       │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/
│                       │     │                  │        │           A:H 
│                       │     │                  │        ╰ V3Score : 7.8 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 8.4 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-34040 
│                       │     │                  ├ [1]: https://docs.docker.com/engine/extend/plugins_authoriza
│                       │     │                  │      tion 
│                       │     │                  ├ [2]: https://github.com/moby/moby 
│                       │     │                  ├ [3]: https://github.com/moby/moby/commit/e89edb19ad7de0407a5
│                       │     │                  │      d31e3111cb01aa10b5a38 
│                       │     │                  ├ [4]: https://github.com/moby/moby/releases/tag/docker-v29.3.1 
│                       │     │                  ├ [5]: https://github.com/moby/moby/security/advisories/GHSA-v
│                       │     │                  │      23v-6jw2-98fq 
│                       │     │                  ├ [6]: https://github.com/moby/moby/security/advisories/GHSA-x
│                       │     │                  │      744-4wpc-v9h2 
│                       │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-34040 
│                       │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-34040 
│                       │     ├ PublishedDate   : 2026-03-31T03:15:57.883Z 
│                       │     ╰ LastModifiedDate: 2026-04-03T16:51:28.67Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-33997 
│                       │     ├ VendorIDs        ─ [0]: GHSA-pxq6-2prw-chj9 
│                       │     ├ PkgID           : github.com/docker/docker@v28.5.2+incompatible 
│                       │     ├ PkgName         : github.com/docker/docker 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v28.5.2%2Bincompat
│                       │     │                  │       ible 
│                       │     │                  ╰ UID : 7900223948e2f444 
│                       │     ├ InstalledVersion: v28.5.2+incompatible 
│                       │     ├ FixedVersion    : 29.3.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33997 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:0be60511564dcdad18abb4989b28a87427e5daa1e8843ae6e879a7
│                       │     │                   fac5a715a4 
│                       │     ├ Title           : moby: docker: github.com/moby/moby: Moby: Privilege
│                       │     │                   validation bypass during plugin installation 
│                       │     ├ Description     : Moby is an open source container framework. Prior to version
│                       │     │                   29.3.1, a security vulnerability has been detected that
│                       │     │                   allows plugins privilege validation to be bypassed during
│                       │     │                   docker plugin install. Due to an error in the daemon's
│                       │     │                   privilege comparison logic, the daemon may incorrectly accept
│                       │     │                    a privilege set that differs from the one approved by the
│                       │     │                   user. Plugins that request exactly one privilege are also
│                       │     │                   affected, because no comparison is performed at all. This
│                       │     │                   issue has been patched in version 29.3.1. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-193 
│                       │     ├ VendorSeverity   ╭ amazon: 2 
│                       │     │                  ├ ghsa  : 2 
│                       │     │                  ├ nvd   : 3 
│                       │     │                  ├ photon: 3 
│                       │     │                  ╰ redhat: 3 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 6.8 
│                       │     │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 8.1 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 8.4 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33997 
│                       │     │                  ├ [1]: https://docs.docker.com/engine/extend/legacy_plugins 
│                       │     │                  ├ [2]: https://github.com/moby/moby 
│                       │     │                  ├ [3]: https://github.com/moby/moby/commit/f4d6f25bf0c3fa12d49
│                       │     │                  │      68320a45685947756a22a 
│                       │     │                  ├ [4]: https://github.com/moby/moby/releases/tag/docker-v29.3.1 
│                       │     │                  ├ [5]: https://github.com/moby/moby/security/advisories/GHSA-p
│                       │     │                  │      xq6-2prw-chj9 
│                       │     │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-33997 
│                       │     │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-33997 
│                       │     ├ PublishedDate   : 2026-03-31T03:15:57.523Z 
│                       │     ╰ LastModifiedDate: 2026-04-03T17:23:21.307Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-33811 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4981 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ SeveritySource  : nvd 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:d6c70925bbaa4a65535c817c567f6bd54a6619a92cc102089a172f
│                       │     │                   9cf6c2ccac 
│                       │     ├ Title           : When using LookupCNAME with the cgo DNS resolver, a very long
│                       │     │                    CNAME re ... 
│                       │     ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very long
│                       │     │                    CNAME response can trigger a double-free of C memory and a
│                       │     │                   crash. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-415 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ nvd    : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/767860 
│                       │     │                  ├ [1]: https://go.dev/issue/78803 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4981 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
│                       │     ╰ LastModifiedDate: 2026-05-12T20:23:02.333Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-33814 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4918 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ SeveritySource  : nvd 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:9011ab8907086730c9ebb0c4892da7f2ac9bd946cb6698512c6b15
│                       │     │                   db214f5d6b 
│                       │     ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │     │                   an infini ... 
│                       │     ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │     │                   an infinite loop of writing CONTINUATION frames if it
│                       │     │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-835 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ nvd    : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/761581 
│                       │     │                  ├ [1]: https://go.dev/cl/761640 
│                       │     │                  ├ [2]: https://go.dev/issue/78476 
│                       │     │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
│                       │     │                  ╰ [5]: https://pkg.go.dev/vuln/GO-2026-4918 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
│                       │     ╰ LastModifiedDate: 2026-05-13T14:41:59.52Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-39820 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4986 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ SeveritySource  : nvd 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:18b50aaad755cb1c1c5c73fe7bbb28102fb13e408bd38c646669d9
│                       │     │                   68c759fa10 
│                       │     ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │     │                   and Parse ... 
│                       │     ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │     │                   and ParseDate were able to trigger excessive CPU exhaustion
│                       │     │                   and memory allocations. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-770 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ nvd    : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/759940 
│                       │     │                  ├ [1]: https://go.dev/issue/78566 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4986 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
│                       │     ╰ LastModifiedDate: 2026-05-13T15:10:58.65Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-39836 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4971 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ SeveritySource  : nvd 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:fd9be0e17de729058e789b65ef1f3b88212063f6043763bd7de2b1
│                       │     │                   6d00ef69a8 
│                       │     ├ Title           : Panic in Dial and LookupPort when handling NUL byte on
│                       │     │                   Windows in net 
│                       │     ├ Description     : The Dial and LookupPort functions panic on Windows when
│                       │     │                   provided with an input containing a NUL (0). 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-476 
│                       │     ├ VendorSeverity   ╭ bitnami: 3 
│                       │     │                  ╰ nvd    : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 7.5 
│                       │     │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/775320 
│                       │     │                  ├ [1]: https://go.dev/issue/79006 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39836 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4971 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:43.593Z 
│                       │     ╰ LastModifiedDate: 2026-05-13T15:11:10.31Z 
│                       ├ [6] ╭ VulnerabilityID : CVE-2026-42499 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4977 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:088b61b592caf542ac58f58a92d9f50abd72b92dc2d031991ce1b2
│                       │     │                   39160eb99d 
│                       │     ├ Title           : Pathological inputs could cause DoS through consumePhrase
│                       │     │                   when parsing ... 
│                       │     ├ Description     : Pathological inputs could cause DoS through consumePhrase
│                       │     │                   when parsing an email address according to RFC 5322. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ VendorSeverity   ─ bitnami: 3 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/771520 
│                       │     │                  ├ [1]: https://go.dev/issue/78987 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4977 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
│                       │     ╰ LastModifiedDate: 2026-05-13T16:59:17.563Z 
│                       ├ [7] ╭ VulnerabilityID : CVE-2026-39823 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4982 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:a6bb72f003734cc45a0d955d0038c65e9ffa6480d034e79f815eef
│                       │     │                   76beb60209 
│                       │     ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │     │                   correctly  ... 
│                       │     ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │     │                   correctly escaped inside of a <meta> tag's <content>
│                       │     │                   attribute. If the URL content were to insert ASCII
│                       │     │                   whitespaces around the '=' rune inside of the <content>
│                       │     │                   attribute, the escaper would fail to similarly escape it,
│                       │     │                   leading to XSS. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-79 
│                       │     ├ VendorSeverity   ─ bitnami: 2 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 6.1 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/769920 
│                       │     │                  ├ [1]: https://go.dev/issue/78913 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39823 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4982 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:43.29Z 
│                       │     ╰ LastModifiedDate: 2026-05-13T16:58:45.697Z 
│                       ├ [8] ╭ VulnerabilityID : CVE-2026-39825 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-4976 
│                       │     ├ PkgID           : stdlib@v1.26.2 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                       │     │                  ╰ UID : 337c063156626aca 
│                       │     ├ InstalledVersion: v1.26.2 
│                       │     ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                       │     │                  │         604d470cc284fe84f9a 
│                       │     │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                       │     │                            9a6ba0df01bfc18beca 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:2c6033e1624016d440a2245e1ec9e5cc2e1b29c6c0d3aef2848163
│                       │     │                   cbff6ebcfd 
│                       │     ├ Title           : ReverseProxy can forward queries containing parameters not
│                       │     │                   visible to  ... 
│                       │     ├ Description     : ReverseProxy can forward queries containing parameters not
│                       │     │                   visible to Rewrite functions. When used with a Rewrite
│                       │     │                   function, or a Director function which parses query
│                       │     │                   parameters, ReverseProxy sanitizes the forwarded request to
│                       │     │                   remove query parameters which are not parsed by
│                       │     │                   url.ParseQuery. ReverseProxy does not take ParseQuery's limit
│                       │     │                    on the total number of query parameters (controlled by
│                       │     │                   GODEBUG=urlmaxqueryparams=N) into account. This can permit
│                       │     │                   ReverseProxy to forward a request containing a query
│                       │     │                   parameter that is not visible to the Rewrite function. For
│                       │     │                   example, the query "a1=x&a2=x&...&a10000=x&hidden=y" can
│                       │     │                   forward the parameter "hidden=y" while hiding it from the
│                       │     │                   proxy's Rewrite function. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ bitnami: 2 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N
│                       │     │                            │           /A:N 
│                       │     │                            ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/770541 
│                       │     │                  ├ [1]: https://go.dev/issue/78948 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39825 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4976 
│                       │     ├ PublishedDate   : 2026-05-07T20:16:43.39Z 
│                       │     ╰ LastModifiedDate: 2026-05-13T16:58:56.39Z 
│                       ╰ [9] ╭ VulnerabilityID : CVE-2026-39826 
│                             ├ VendorIDs        ─ [0]: GO-2026-4980 
│                             ├ PkgID           : stdlib@v1.26.2 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
│                             │                  ╰ UID : 337c063156626aca 
│                             ├ InstalledVersion: v1.26.2 
│                             ├ FixedVersion    : 1.25.10, 1.26.3 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1e
│                             │                  │         604d470cc284fe84f9a 
│                             │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919c
│                             │                            9a6ba0df01bfc18beca 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:e7079255b870764a2bd1c93cb858394e31358f68def18567421466
│                             │                   432fb1735f 
│                             ├ Title           : If a trusted template author were to write a <script> tag
│                             │                   containing a ... 
│                             ├ Description     : If a trusted template author were to write a <script> tag
│                             │                   containing an empty 'type' attribute or a 'type' attribute
│                             │                   with an ASCII whitespace, the execution of the template would
│                             │                    incorrectly escape any data passed into the <script>
│                             │                   block. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-116 
│                             ├ VendorSeverity   ─ bitnami: 2 
│                             ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                             │                            │           /A:N 
│                             │                            ╰ V3Score : 6.1 
│                             ├ References       ╭ [0]: https://go.dev/cl/771180 
│                             │                  ├ [1]: https://go.dev/issue/78981 
│                             │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso47M 
│                             │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
│                             │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4980 
│                             ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
│                             ╰ LastModifiedDate: 2026-05-13T16:59:07.48Z 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32952 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:af2395ecc8ba0921425309cbdf1f04eecf3a90b7c61ac1bbc4196
│                       │      │                   113b9f71097 
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
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 5.3 
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
│                       │      ╰ LastModifiedDate: 2026-04-24T14:50:56.203Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-41602 
│                       │      ├ VendorIDs        ─ [0]: GHSA-wf45-q9ch-q8gh 
│                       │      ├ PkgID           : github.com/apache/thrift@v0.22.0 
│                       │      ├ PkgName         : github.com/apache/thrift 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/apache/thrift@v0.22.0 
│                       │      │                  ╰ UID : 7cca386d01b6c3b2 
│                       │      ├ InstalledVersion: v0.22.0 
│                       │      ├ FixedVersion    : 0.23.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41602 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:63799a047b2fe8d80efa5bcde47151301713719f1bf00e8252c86
│                       │      │                   08188ec991a 
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
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://github.com/advisories/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:b9ef86c655e035c998f12c25e676a869dbb133be9704f31aef008
│                       │      │                   22596874f45 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://github.com/advisories/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:0ccb6e08c9268bc376a6ca09578ba857e85bcf590064d997ea642
│                       │      │                   0e674e46d82 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://github.com/advisories/GHSA-xmrv-pmrh-hhx2 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:7c917ef878c7635c67463bb994f495c4248bde236a4fe0adf13bf
│                       │      │                   92331b78040 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21726 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:93ea60c0e5b11ecf73b73d4a48bb936d6d581bf5002a92d35964e
│                       │      │                   4cb5c31147a 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:3d7c7eac66225185ae4ebe30e55fcb2004c3760793632b9b591d3
│                       │      │                   dfd3d88546d 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:162e5ffa3900ebe905242053d4174fbcd938486f0115a38980ef9
│                       │      │                   aa461120909 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33816 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:2b0ea3c99463d738e9ac0688894033d1e8e7918c255b5716ef4e0
│                       │      │                   eeeae68c4a5 
│                       │      ├ Title           : github.com/jackc/pgx/v5: github.com/jackc/pgx: Memory-safety
│                       │      │                    vulnerability 
│                       │      ├ Description     : Memory-safety vulnerability in github.com/jackc/pgx/v5. 
│                       │      ├ Severity        : CRITICAL 
│                       │      ├ VendorSeverity   ╭ ghsa  : 4 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 8.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33816 
│                       │      │                  ├ [1]: https://github.com/jackc/pgx 
│                       │      │                  ├ [2]: https://nvd.nist.gov/vuln/detail/CVE-2026-33816 
│                       │      │                  ├ [3]: https://pkg.go.dev/vuln/GO-2026-4772 
│                       │      │                  ╰ [4]: https://www.cve.org/CVERecord?id=CVE-2026-33816 
│                       │      ├ PublishedDate   : 2026-04-07T16:16:24.92Z 
│                       │      ╰ LastModifiedDate: 2026-04-14T20:01:07.16Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-41889 
│                       │      ├ VendorIDs        ─ [0]: GHSA-j88v-2chj-qfwx 
│                       │      ├ PkgID           : github.com/jackc/pgx/v5@v5.8.0 
│                       │      ├ PkgName         : github.com/jackc/pgx/v5 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/jackc/pgx/v5@v5.8.0 
│                       │      │                  ╰ UID : 2c685c55374d6682 
│                       │      ├ InstalledVersion: v5.8.0 
│                       │      ├ FixedVersion    : 5.9.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41889 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:5a2c07264722e03466b536adf2f84c368fce6c62ffd6f63fdeda5
│                       │      │                   c9e76970fa6 
│                       │      ├ Title           : pgx is a PostgreSQL driver and toolkit for Go. Prior to
│                       │      │                   version 5.9.2, ... 
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
│                       │      ├ VendorSeverity   ─ ghsa: 1 
│                       │      ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:N/VI
│                       │      │                         │            :L/VA:N/SC:N/SI:N/SA:N 
│                       │      │                         ╰ V40Score : 2.3 
│                       │      ├ References       ╭ [0]: https://github.com/jackc/pgx 
│                       │      │                  ├ [1]: https://github.com/jackc/pgx/commit/60644f84918a8af66d
│                       │      │                  │      14a4b0d865d4edafd955da 
│                       │      │                  ├ [2]: https://github.com/jackc/pgx/releases/tag/v5.9.2 
│                       │      │                  ├ [3]: https://github.com/jackc/pgx/security/advisories/GHSA-
│                       │      │                  │      j88v-2chj-qfwx 
│                       │      │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-41889 
│                       │      ├ PublishedDate   : 2026-05-08T17:16:31.04Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T16:34:56.063Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-34040 
│                       │      ├ VendorIDs        ─ [0]: GHSA-x744-4wpc-v9h2 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ FixedVersion    : 29.3.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-34040 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:da4d0c56730e21ee68e32fc29ab634ff78b48c8aabfa4441ef929
│                       │      │                   3a046116e8a 
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
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-33997 
│                       │      ├ VendorIDs        ─ [0]: GHSA-pxq6-2prw-chj9 
│                       │      ├ PkgID           : github.com/moby/moby@v28.5.2+incompatible 
│                       │      ├ PkgName         : github.com/moby/moby 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/moby/moby@v28.5.2%2Bincompatible 
│                       │      │                  ╰ UID : 39939611a6867a05 
│                       │      ├ InstalledVersion: v28.5.2+incompatible 
│                       │      ├ FixedVersion    : 29.3.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33997 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:d4104a4d151fb6ada0dc20a70598a9fd37d1b8f064c57474b3015
│                       │      │                   8396af00cca 
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
│                       ├ [12] ╭ VulnerabilityID : CVE-2026-33729 
│                       │      ├ VendorIDs        ─ [0]: GHSA-h6c8-cww8-35hf 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.13.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33729 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ee588ebc4a8acc8553f129734a997f57b19d76f192d78ee0d774d
│                       │      │                   392904fd166 
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
│                       ├ [13] ╭ VulnerabilityID : CVE-2026-34972 
│                       │      ├ VendorIDs        ─ [0]: GHSA-jwvj-g8pc-cx45 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.14.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-34972 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:19ee39d57f248c4526b9e240fcf3aa44661626e6f21c0aac0c16b
│                       │      │                   b9d43ea017b 
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
│                       ├ [14] ╭ VulnerabilityID : CVE-2026-40293 
│                       │      ├ VendorIDs        ─ [0]: GHSA-68m9-983m-f3v5 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.14.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40293 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:6af3c4e21e26f0045a1e2f283c788123fc4c2fd439c1401f53cee
│                       │      │                   fdd054ad042 
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
│                       ├ [15] ╭ VulnerabilityID : CVE-2026-41131 
│                       │      ├ VendorIDs        ─ [0]: GHSA-57j5-qwp2-vqp6 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.11.3 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.11.3 
│                       │      │                  ╰ UID : 543a9e2713c17753 
│                       │      ├ InstalledVersion: v1.11.3 
│                       │      ├ FixedVersion    : 1.14.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-41131 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:70636de60a3d74ae12ccb47eb088e38b556a3239adf975800c0bf
│                       │      │                   d7f8147b774 
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
│                       ├ [16] ╭ VulnerabilityID : CVE-2026-42151 
│                       │      ├ VendorIDs        ─ [0]: GHSA-wg65-39gg-5wfj 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42151 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:7b2186e8b9609eb4120413e6425707c8ae46e6af2517c63907ebc
│                       │      │                   2cc28030aaa 
│                       │      ├ Title           : Prometheus is an open-source monitoring system and time
│                       │      │                   series databas ... 
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
│                       │      │                  ╰ ghsa   : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus/pull/18587 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/pull/18590 
│                       │      │                  ├ [3]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.11.3 
│                       │      │                  ├ [4]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.5.3 
│                       │      │                  ├ [5]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-wg65-39gg-5wfj 
│                       │      │                  ╰ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-42151 
│                       │      ├ PublishedDate   : 2026-05-04T19:16:04.22Z 
│                       │      ╰ LastModifiedDate: 2026-05-11T17:22:07.227Z 
│                       ├ [17] ╭ VulnerabilityID : CVE-2026-42154 
│                       │      ├ VendorIDs        ─ [0]: GHSA-8rm2-7qqf-34qm 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42154 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:6496a378e6b56d8f57951fd108e4d25d98934376ab2b20f9206dd
│                       │      │                   5adc70728be 
│                       │      ├ Title           : Prometheus is an open-source monitoring system and time
│                       │      │                   series databas ... 
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
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ ghsa   : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus/pull/18584 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/pull/18585 
│                       │      │                  ├ [3]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.11.3 
│                       │      │                  ├ [4]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.5.3 
│                       │      │                  ├ [5]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-8rm2-7qqf-34qm 
│                       │      │                  ╰ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-42154 
│                       │      ├ PublishedDate   : 2026-05-04T19:16:04.397Z 
│                       │      ╰ LastModifiedDate: 2026-05-11T17:22:42.86Z 
│                       ├ [18] ╭ VulnerabilityID : CVE-2026-40179 
│                       │      ├ VendorIDs        ─ [0]: GHSA-vffh-x6r8-xx99 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.2-0.20260410083055-07c6232d159b 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40179 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:9672d69f4b857c2d1d4ac558363792b34404e935a2215fa426470
│                       │      │                   2d75474df49 
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
│                       ├ [19] ╭ VulnerabilityID : CVE-2026-44903 
│                       │      ├ VendorIDs        ─ [0]: GHSA-fw8g-cg8f-9j28 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.303.1 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.303.1 
│                       │      │                  ╰ UID : 67407d99c8563d1b 
│                       │      ├ InstalledVersion: v0.303.1 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-44903 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:7766b1c9c89bc291b27542539e5e6a0400e84e0ded9fca93e1643
│                       │      │                   e2817f4f0ee 
│                       │      ├ Title           : Prometheus vulnerable to stored XSS via crafted histogram
│                       │      │                   bucket label values in the old web UI heatmap display 
│                       │      ├ Description     : ### Impact
│                       │      │                   
│                       │      │                   In the Prometheus server's legacy web UI (enabled via the
│                       │      │                   command-line flag `--enable-feature=old-ui`), the histogram
│                       │      │                   heatmap chart view does not escape `le` label values when
│                       │      │                   inserting them into the HTML for use as axis tick mark
│                       │      │                   labels.
│                       │      │                   An attacker who can inject crafted metrics (e.g. via a
│                       │      │                   compromised scrape target, remote write, or OTLP receiver
│                       │      │                   endpoint) can execute JavaScript in the browser of any
│                       │      │                   Prometheus user who views the metric in the heatmap chart
│                       │      │                   UI. From the XSS context, an attacker could for example:
│                       │      │                   - Read `/api/v1/status/config` to extract sensitive
│                       │      │                   configuration (although credentials / secrets are redacted
│                       │      │                   by the server)
│                       │      │                   - Call `/-/quit` to shut down Prometheus (only if
│                       │      │                   `--web.enable-lifecycle` is set)
│                       │      │                   - Call `/api/v1/admin/tsdb/delete_series` to delete data
│                       │      │                   (only if `--web.enable-admin-api` is set)
│                       │      │                   - Exfiltrate metric data to an external server
│                       │      │                   Note that this only affects users who have explicitly
│                       │      │                   enabled the legacy Prometheus web UI using the
│                       │      │                   `--enable-feature=old-ui` command-line flag.
│                       │      │                   ### Patches
│                       │      │                   https://github.com/prometheus/prometheus/commit/38f23b9075ce
│                       │      │                   d1de2b82d2dad8b2bebb1ecd5b7d
│                       │      │                   ### Workarounds
│                       │      │                   If at all possible, disable the legacy web UI by removing
│                       │      │                   the `--enable-feature=old-ui` command-line flag).
│                       │      │                   If this is not an option, take the following precautions:
│                       │      │                   - If using the remote write receiver
│                       │      │                   (`--web.enable-remote-write-receiver`), ensure it is not
│                       │      │                   exposed to untrusted sources.
│                       │      │                   - If using the OTLP receiver (`--web.enable-otlp-receiver`),
│                       │      │                    ensure it is not exposed to untrusted sources.
│                       │      │                   - Ensure scrape targets are trusted and not under attacker
│                       │      │                   control.
│                       │      │                   - Do not enable admin / mutating API endpoints (e.g.
│                       │      │                   `--web.enable-admin-api` or `web.enable-lifecycle`) in cases
│                       │      │                    where you cannot prevent untrusted data from being
│                       │      │                   ingested.
│                       │      │                   - Users should avoid clicking untrusted links, especially
│                       │      │                   those containing functions such as `label_replace`, as they
│                       │      │                   may generate poisoned label names and values.
│                       │      │                   ### References
│                       │      │                   - CVE-2019-10215 — prior stored DOM XSS vulnerability in
│                       │      │                   Prometheus query history, fixed in v2.7.2
│                       │      │                   - CVE-2026-40179 — prior stored DOM XSS vulnerability in
│                       │      │                   Prometheus web UI (hover tooltips and metrics explorer),
│                       │      │                   fixed in v3.11.2 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ╰ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │                         ├ [1]: https://github.com/prometheus/prometheus/commit/38f23b
│                       │                         │      9075ced1de2b82d2dad8b2bebb1ecd5b7d 
│                       │                         ╰ [2]: https://github.com/prometheus/prometheus/security/advi
│                       │                                sories/GHSA-fw8g-cg8f-9j28 
│                       ├ [20] ╭ VulnerabilityID : CVE-2026-39882 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:555c7ce6f18b5768a641b007630a56c2bb69ef54e4b06624ba057
│                       │      │                   7b2876be14c 
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
│                       │      ├ VendorSeverity   ╭ amazon: 2 
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
│                       ├ [21] ╭ VulnerabilityID : CVE-2026-39882 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:2d9ec9a7d590d55a006bd4fb39132c04f00d0772b50fe02229700
│                       │      │                   8a350fff49f 
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
│                       │      ├ VendorSeverity   ╭ amazon: 2 
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
│                       ├ [22] ╭ VulnerabilityID : CVE-2026-39882 
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
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39882 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:0a9745107b6d021333001042a27da4c86f47e3968f1a51b5034d7
│                       │      │                   25576f1f9d3 
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
│                       │      ├ VendorSeverity   ╭ amazon: 2 
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
│                       ├ [23] ╭ VulnerabilityID : CVE-2026-39883 
│                       │      ├ VendorIDs        ─ [0]: GHSA-hfvc-g4fc-pqhx 
│                       │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.42.0 
│                       │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.42.0 
│                       │      │                  ╰ UID : 9f0357f06426b992 
│                       │      ├ InstalledVersion: v1.42.0 
│                       │      ├ FixedVersion    : 1.43.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:c9b9dec846abf21173512ca321acbc706f5389dd0d1278cd73cf8
│                       │      │                   f30195333d7 
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
│                       ├ [24] ╭ VulnerabilityID : CVE-2026-33811 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4981 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:81763453017bc728e242a56306ce85d595e0c98f623eaf70b73a2
│                       │      │                   849c8395b0d 
│                       │      ├ Title           : When using LookupCNAME with the cgo DNS resolver, a very
│                       │      │                   long CNAME re ... 
│                       │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
│                       │      │                   long CNAME response can trigger a double-free of C memory
│                       │      │                   and a crash. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-415 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ nvd    : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/767860 
│                       │      │                  ├ [1]: https://go.dev/issue/78803 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4981 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
│                       │      ╰ LastModifiedDate: 2026-05-12T20:23:02.333Z 
│                       ├ [25] ╭ VulnerabilityID : CVE-2026-33814 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4918 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:adb6155d22a6485c1955a30e6e6aaf0bc7446262d167b68d2518b
│                       │      │                   0459d7fd799 
│                       │      ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │      │                    an infini ... 
│                       │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
│                       │      │                    an infinite loop of writing CONTINUATION frames if it
│                       │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-835 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ╰ nvd    : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/761581 
│                       │      │                  ├ [1]: https://go.dev/cl/761640 
│                       │      │                  ├ [2]: https://go.dev/issue/78476 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                       │      │                  │      47M 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
│                       │      │                  ╰ [5]: https://pkg.go.dev/vuln/GO-2026-4918 
│                       │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
│                       │      ╰ LastModifiedDate: 2026-05-13T14:41:59.52Z 
│                       ├ [26] ╭ VulnerabilityID : CVE-2026-39820 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4986 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:fd9aa2922be8326743f306a338be9e6014b09c8534ba28d065975
│                       │      │                   93740d014f4 
│                       │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │      │                    and Parse ... 
│                       │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
│                       │      │                    and ParseDate were able to trigger excessive CPU exhaustion
│                       │      │                    and memory allocations. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-770 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
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
│                       ├ [27] ╭ VulnerabilityID : CVE-2026-39836 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4971 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ SeveritySource  : nvd 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5c4431a3aad5e093e33c9cee5afb2ea84c283ef8162fd5807a763
│                       │      │                   58f7adb9920 
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
│                       ├ [28] ╭ VulnerabilityID : CVE-2026-42499 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4977 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5208c0c73295eb5b8213b208b3de281982f8bf5c366fb8edfa980
│                       │      │                   18edd123d2e 
│                       │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
│                       │      │                   when parsing ... 
│                       │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
│                       │      │                   when parsing an email address according to RFC 5322. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ VendorSeverity   ─ bitnami: 3 
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
│                       ├ [29] ╭ VulnerabilityID : CVE-2026-39823 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4982 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:3c06e88b1ce91b5571631ed302db4495a89fb73ff14c079ceb22d
│                       │      │                   9f6bb104b74 
│                       │      ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │      │                   correctly  ... 
│                       │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
│                       │      │                   correctly escaped inside of a <meta> tag's <content>
│                       │      │                   attribute. If the URL content were to insert ASCII
│                       │      │                   whitespaces around the '=' rune inside of the <content>
│                       │      │                   attribute, the escaper would fail to similarly escape it,
│                       │      │                   leading to XSS. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ─ bitnami: 2 
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
│                       ├ [30] ╭ VulnerabilityID : CVE-2026-39825 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-4976 
│                       │      ├ PkgID           : stdlib@v1.25.9 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                       │      │                  ╰ UID : 2f9d47014fd0da0e 
│                       │      ├ InstalledVersion: v1.25.9 
│                       │      ├ FixedVersion    : 1.25.10, 1.26.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                       │      │                  │         e604d470cc284fe84f9a 
│                       │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                       │      │                            c9a6ba0df01bfc18beca 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:54383760ccc594ed2cdf2ac5b16aa3c48085010c89f86bf14823b
│                       │      │                   def1e0edb12 
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
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ bitnami: 2 
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
│                       ╰ [31] ╭ VulnerabilityID : CVE-2026-39826 
│                              ├ VendorIDs        ─ [0]: GO-2026-4980 
│                              ├ PkgID           : stdlib@v1.25.9 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.9 
│                              │                  ╰ UID : 2f9d47014fd0da0e 
│                              ├ InstalledVersion: v1.25.9 
│                              ├ FixedVersion    : 1.25.10, 1.26.3 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
│                              │                  │         e604d470cc284fe84f9a 
│                              │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
│                              │                            c9a6ba0df01bfc18beca 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:e88219983debee1a3e2a2c364624883c1d2e6903518f0ac8ca5e7
│                              │                   c952b3ca4f3 
│                              ├ Title           : If a trusted template author were to write a <script> tag
│                              │                   containing a ... 
│                              ├ Description     : If a trusted template author were to write a <script> tag
│                              │                   containing an empty 'type' attribute or a 'type' attribute
│                              │                   with an ASCII whitespace, the execution of the template
│                              │                   would incorrectly escape any data passed into the <script>
│                              │                   block. 
│                              ├ Severity        : MEDIUM 
│                              ├ CweIDs           ─ [0]: CWE-116 
│                              ├ VendorSeverity   ─ bitnami: 2 
│                              ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 6.1 
│                              ├ References       ╭ [0]: https://go.dev/cl/771180 
│                              │                  ├ [1]: https://go.dev/issue/78981 
│                              │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
│                              │                  │      47M 
│                              │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39826 
│                              │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4980 
│                              ├ PublishedDate   : 2026-05-07T20:16:43.49Z 
│                              ╰ LastModifiedDate: 2026-05-13T16:59:07.48Z 
╰ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
      │                  rce_linux_amd64 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ├ Packages        
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-39883 
                        │      ├ VendorIDs        ─ [0]: GHSA-hfvc-g4fc-pqhx 
                        │      ├ PkgID           : go.opentelemetry.io/otel/sdk@v1.42.0 
                        │      ├ PkgName         : go.opentelemetry.io/otel/sdk 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/go.opentelemetry.io/otel/sdk@v1.42.0 
                        │      │                  ╰ UID : d4f95241340762e7 
                        │      ├ InstalledVersion: v1.42.0 
                        │      ├ FixedVersion    : 1.43.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:07c4e8152af3e9ce1580d63ccfdbc64360bcfd6b2ccbeddd6e067
                        │      │                   291d97eb7ba 
                        │      ├ Title           : opentelemetry-go: BSD kenv command not using absolute path
                        │      │                   enables PATH hijacking 
                        │      ├ Description     : OpenTelemetry-Go is the Go implementation of OpenTelemetry.
                        │      │                   From 1.15.0 to 1.42.0, the fix for CVE-2026-24051 changed
                        │      │                   the Darwin ioreg command to use an absolute path but left
                        │      │                   the BSD kenv command using a bare name, allowing the same
                        │      │                   PATH hijacking attack on BSD and Solaris platforms. This
                        │      │                   vulnerability is fixed in 1.43.0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-426 
                        │      ├ VendorSeverity   ╭ ghsa: 3 
                        │      │                  ╰ nvd : 3 
                        │      ├ CVSS             ╭ ghsa ╭ V40Vector: CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI
                        │      │                  │      │            :H/VA:H/SC:N/SI:N/SA:N 
                        │      │                  │      ╰ V40Score : 7.3 
                        │      │                  ╰ nvd  ╭ V3Vector: CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H 
                        │      │                         ╰ V3Score : 7 
                        │      ├ References       ╭ [0]: http://github.com/open-telemetry/opentelemetry-go/rele
                        │      │                  │      ases/tag/v1.43.0 
                        │      │                  ├ [1]: https://github.com/open-telemetry/opentelemetry-go 
                        │      │                  ├ [2]: https://github.com/open-telemetry/opentelemetry-go/sec
                        │      │                  │      urity/advisories/GHSA-hfvc-g4fc-pqhx 
                        │      │                  ╰ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39883 
                        │      ├ PublishedDate   : 2026-04-08T21:17:00.697Z 
                        │      ╰ LastModifiedDate: 2026-04-10T21:16:27.12Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2026-25679 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4601 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.8, 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25679 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:74444f874f0c259d1cf88000cbddbe1ec2e199820a3ed53a29c4a
                        │      │                   76548035c31 
                        │      ├ Title           : net/url: Incorrect parsing of IPv6 host literals in net/url 
                        │      ├ Description     : url.Parse insufficiently validated the host/authority
                        │      │                   component and accepted some invalid URLs. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-425 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ azure      : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:9044 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-25679 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2026-9044.html 
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:8841 
                        │      │                  ├ [7] : https://go.dev/cl/752180 
                        │      │                  ├ [8] : https://go.dev/issue/77578 
                        │      │                  ├ [9] : https://groups.google.com/g/golang-announce/c/EdhZqrQ
                        │      │                  │       98hk 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2026-25679.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2026-9044.html 
                        │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2026-25679 
                        │      │                  ├ [13]: https://pkg.go.dev/vuln/GO-2026-4601 
                        │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2026-25679 
                        │      ├ PublishedDate   : 2026-03-06T22:16:00.72Z 
                        │      ╰ LastModifiedDate: 2026-04-21T14:43:03.8Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-27137 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4599 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27137 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cf6ef9a718641475710f32fae0aa08d7ef84fa1ce006d22fe4dcf
                        │      │                   623c77fd848 
                        │      ├ Title           : crypto/x509: Incorrect enforcement of email constraints in
                        │      │                   crypto/x509 
                        │      ├ Description     : When verifying a certificate chain which contains a
                        │      │                   certificate containing multiple email address constraints
                        │      │                   which share common local portions but different domain
                        │      │                   portions, these constraints will not be properly applied,
                        │      │                   and only the last constraint will be considered. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ azure      : 2 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:8842 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-27137 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2445345 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2445345 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [6] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [7] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-27137 
                        │      │                  ├ [8] : https://errata.almalinux.org/10/ALSA-2026-8842.html 
                        │      │                  ├ [9] : https://errata.rockylinux.org/RLSA-2026:8842 
                        │      │                  ├ [10]: https://go.dev/cl/752182 
                        │      │                  ├ [11]: https://go.dev/issue/77952 
                        │      │                  ├ [12]: https://groups.google.com/g/golang-announce/c/EdhZqrQ
                        │      │                  │       98hk 
                        │      │                  ├ [13]: https://linux.oracle.com/cve/CVE-2026-27137.html 
                        │      │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2026-8842.html 
                        │      │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2026-27137 
                        │      │                  ├ [16]: https://pkg.go.dev/vuln/GO-2026-4599 
                        │      │                  ╰ [17]: https://www.cve.org/CVERecord?id=CVE-2026-27137 
                        │      ├ PublishedDate   : 2026-03-06T22:16:00.85Z 
                        │      ╰ LastModifiedDate: 2026-04-21T14:40:31.187Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-32280 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4947 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32280 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0df4086264614c02f0b68cb639401646b06c4cd34a0550d18da57
                        │      │                   cb825f2f076 
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
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:14200 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-32280 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2456336 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2456336 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [8] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [9] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32282 
                        │      │                  ├ [10]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2026-14200.html 
                        │      │                  ├ [12]: https://errata.rockylinux.org/RLSA-2026:14200 
                        │      │                  ├ [13]: https://go.dev/cl/758320 
                        │      │                  ├ [14]: https://go.dev/issue/78282 
                        │      │                  ├ [15]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [16]: https://linux.oracle.com/cve/CVE-2026-32280.html 
                        │      │                  ├ [17]: https://linux.oracle.com/errata/ELSA-2026-16875.html 
                        │      │                  ├ [18]: https://nvd.nist.gov/vuln/detail/CVE-2026-32280 
                        │      │                  ├ [19]: https://pkg.go.dev/vuln/GO-2026-4947 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2026-32280 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.247Z 
                        │      ╰ LastModifiedDate: 2026-04-16T19:16:42.18Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-32281 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4946 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32281 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0b7c5f133d86646a2839f6934a4aa5f1f4eb13ea9d1ee06eeb303
                        │      │                   7a8ae53f0dc 
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
                        │      ├ VendorSeverity   ╭ amazon : 2 
                        │      │                  ├ bitnami: 3 
                        │      │                  ├ nvd    : 3 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 5.9 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-32281 
                        │      │                  ├ [1]: https://go.dev/cl/758061 
                        │      │                  ├ [2]: https://go.dev/issue/78281 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/0uYbvbPZ
                        │      │                  │      RWU 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-32281 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4946 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-32281 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.35Z 
                        │      ╰ LastModifiedDate: 2026-04-16T19:15:57.75Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-32283 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4870 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32283 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f9aaf5e2e8809dbeb38d12ab23f3b01125a5fb4c36f4289e77f94
                        │      │                   a507c9e924a 
                        │      ├ Title           : crypto/tls: golang: Go crypto/tls: Denial of Service via
                        │      │                   multiple TLS 1.3 key update messages 
                        │      ├ Description     : If one side of the TLS connection sends multiple key update
                        │      │                   messages post-handshake in a single record, the connection
                        │      │                   can deadlock, causing uncontrolled consumption of resources.
                        │      │                    This can lead to a denial of service. This only affects TLS
                        │      │                    1.3. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:14200 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-32283 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2456336 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2456336 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [8] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [9] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32282 
                        │      │                  ├ [10]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2026-14200.html 
                        │      │                  ├ [12]: https://errata.rockylinux.org/RLSA-2026:14200 
                        │      │                  ├ [13]: https://go.dev/cl/763767 
                        │      │                  ├ [14]: https://go.dev/issue/78334 
                        │      │                  ├ [15]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [16]: https://linux.oracle.com/cve/CVE-2026-32283.html 
                        │      │                  ├ [17]: https://linux.oracle.com/errata/ELSA-2026-17075.html 
                        │      │                  ├ [18]: https://nvd.nist.gov/vuln/detail/CVE-2026-32283 
                        │      │                  ├ [19]: https://pkg.go.dev/vuln/GO-2026-4870 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2026-32283 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.58Z 
                        │      ╰ LastModifiedDate: 2026-04-16T19:12:10.54Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-33810 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4866 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33810 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:38494b1313beea4fd1294139db50fbcc61a017230aa66c182f5e2
                        │      │                   cbc2031152e 
                        │      ├ Title           : crypto/x509: golang: Go crypto/x509: Certificate validation
                        │      │                   bypass due to incorrect DNS constraint application 
                        │      ├ Description     : When verifying a certificate chain containing excluded DNS
                        │      │                   constraints, these constraints are not correctly applied to
                        │      │                   wildcard DNS SANs which use a different case than the
                        │      │                   constraint. This only affects validation of otherwise
                        │      │                   trusted certificate chains, issued by a root CA in the
                        │      │                   VerifyOptions.Roots CertPool, or in the system certificate
                        │      │                   pool. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ azure  : 2 
                        │      │                  ├ bitnami: 3 
                        │      │                  ├ nvd    : 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 8.2 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 8.2 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:
                        │      │                            │           L/A:L 
                        │      │                            ╰ V3Score : 8.8 
                        │      ├ References       ╭ [0]: http://www.openwall.com/lists/oss-security/2026/04/19/4 
                        │      │                  ├ [1]: http://www.openwall.com/lists/oss-security/2026/04/20/1 
                        │      │                  ├ [2]: https://access.redhat.com/security/cve/CVE-2026-33810 
                        │      │                  ├ [3]: https://go.dev/cl/763763 
                        │      │                  ├ [4]: https://go.dev/issue/78332 
                        │      │                  ├ [5]: https://groups.google.com/g/golang-announce/c/0uYbvbPZ
                        │      │                  │      RWU 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-33810 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4866 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-33810 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.95Z 
                        │      ╰ LastModifiedDate: 2026-04-20T18:16:26.813Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-33811 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4981 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2da7c6243fc9d1522b09f040d55e4f3bb70120daff8c6c38d71b1
                        │      │                   d17c8fe1e1c 
                        │      ├ Title           : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME re ... 
                        │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME response can trigger a double-free of C memory
                        │      │                   and a crash. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-415 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ nvd    : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/767860 
                        │      │                  ├ [1]: https://go.dev/issue/78803 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
                        │      ╰ LastModifiedDate: 2026-05-12T20:23:02.333Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:da481b9864d87d77a1d1eb8407c003c869238987551e12aca20a8
                        │      │                   94f08e0afc8 
                        │      ├ Title           : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infini ... 
                        │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infinite loop of writing CONTINUATION frames if it
                        │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ╰ nvd    : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/761581 
                        │      │                  ├ [1]: https://go.dev/cl/761640 
                        │      │                  ├ [2]: https://go.dev/issue/78476 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ╰ [5]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-05-13T14:41:59.52Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-39820 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4986 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:ed578248dea0d0d6efcd8a6dd9da8266f8ed0ca8e8cfd0d0f939f
                        │      │                   9f8e056539c 
                        │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and Parse ... 
                        │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and ParseDate were able to trigger excessive CPU exhaustion
                        │      │                    and memory allocations. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
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
                        ├ [10] ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:47baa4a075b7c4347a1a74388d303e19ece0fee0a9b299853a453
                        │      │                   bf89652fdb3 
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
                        ├ [11] ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:1ea54589e14a9c29cb8e91e382a69b25cbb7a58c985570f845975
                        │      │                   4edc06e6843 
                        │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing ... 
                        │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing an email address according to RFC 5322. 
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ─ bitnami: 3 
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
                        ├ [12] ╭ VulnerabilityID : CVE-2026-27142 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4603 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.8, 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27142 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d7b4c267bd33fa010605da46a18e24740798babe404ae2e9efa8d
                        │      │                   27cd1a9c92b 
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
                        │      ╰ LastModifiedDate: 2026-04-21T14:30:01.38Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-32282 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4864 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32282 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2540e68a36b04db842d06caaf48eb97481f420e0f25d87274ec9a
                        │      │                   b8fe5badf6b 
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
                        │      │                  ├ amazon     : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 3 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:14200 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-32282 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2456336 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/show_bug.cgi?id=2456336 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [8] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [9] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32282 
                        │      │                  ├ [10]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2026-14200.html 
                        │      │                  ├ [12]: https://errata.rockylinux.org/RLSA-2026:14200 
                        │      │                  ├ [13]: https://go.dev/cl/763761 
                        │      │                  ├ [14]: https://go.dev/issue/78293 
                        │      │                  ├ [15]: https://groups.google.com/g/golang-announce/c/0uYbvbP
                        │      │                  │       ZRWU 
                        │      │                  ├ [16]: https://linux.oracle.com/cve/CVE-2026-32282.html 
                        │      │                  ├ [17]: https://linux.oracle.com/errata/ELSA-2026-17075.html 
                        │      │                  ├ [18]: https://nvd.nist.gov/vuln/detail/CVE-2026-32282 
                        │      │                  ├ [19]: https://pkg.go.dev/vuln/GO-2026-4864 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2026-32282 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.467Z 
                        │      ╰ LastModifiedDate: 2026-04-16T19:15:39.4Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-32288 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4869 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32288 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:845ffdb2b651e43854aaed28248c1c340a2db643aba81219510ba
                        │      │                   a30494885ae 
                        │      ├ Title           : archive/tar: golang: Go's archive/tar package: Denial of
                        │      │                   Service via maliciously-crafted archive 
                        │      ├ Description     : tar.Reader can allocate an unbounded amount of memory when
                        │      │                   reading a maliciously-crafted archive containing a large
                        │      │                   number of sparse regions encoded in the "old GNU sparse map"
                        │      │                    format. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ amazon : 2 
                        │      │                  ├ azure  : 2 
                        │      │                  ├ bitnami: 2 
                        │      │                  ├ nvd    : 2 
                        │      │                  ├ photon : 2 
                        │      │                  ╰ redhat : 2 
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
                        │      ╰ LastModifiedDate: 2026-04-16T19:08:52.24Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2026-32289 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4865 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32289 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0e7114d2abbf9a03d7ae84c4d5a57e9e5477ca23b5261a8c0b955
                        │      │                   7287fb70fd0 
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
                        │      ├ VendorSeverity   ╭ amazon : 2 
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
                        │      ╰ LastModifiedDate: 2026-04-16T19:06:57.367Z 
                        ├ [16] ╭ VulnerabilityID : CVE-2026-39823 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4982 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:a9a15e4292eb734e727aeb0dd1ea0d54a8cc306c5cce5f93cecb1
                        │      │                   3242cd553ed 
                        │      ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly  ... 
                        │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly escaped inside of a <meta> tag's <content>
                        │      │                   attribute. If the URL content were to insert ASCII
                        │      │                   whitespaces around the '=' rune inside of the <content>
                        │      │                   attribute, the escaper would fail to similarly escape it,
                        │      │                   leading to XSS. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ─ bitnami: 2 
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
                        ├ [17] ╭ VulnerabilityID : CVE-2026-39825 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4976 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:58dd1baded10813fad2e4db1b37771d39ee1f37ea0de7e4ae888a
                        │      │                   52a758a34fc 
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
                        │      ├ Severity        : MEDIUM 
                        │      ├ VendorSeverity   ─ bitnami: 2 
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
                        ├ [18] ╭ VulnerabilityID : CVE-2026-39826 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4980 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7563985a027e96b18e582a6508861f80d4975c25ff7b89201e99d
                        │      │                   5cc6eb90df7 
                        │      ├ Title           : If a trusted template author were to write a <script> tag
                        │      │                   containing a ... 
                        │      ├ Description     : If a trusted template author were to write a <script> tag
                        │      │                   containing an empty 'type' attribute or a 'type' attribute
                        │      │                   with an ASCII whitespace, the execution of the template
                        │      │                   would incorrectly escape any data passed into the <script>
                        │      │                   block. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-116 
                        │      ├ VendorSeverity   ─ bitnami: 2 
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
                        ├ [19] ╭ VulnerabilityID : CVE-2026-27138 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4600 
                        │      ├ PkgID           : stdlib@v1.26.0 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                        │      │                  ╰ UID : 8d6cb282fd98a7ac 
                        │      ├ InstalledVersion: v1.26.0 
                        │      ├ FixedVersion    : 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                        │      │                  │         e604d470cc284fe84f9a 
                        │      │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                        │      │                            c9a6ba0df01bfc18beca 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27138 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:47435199ecb2674946bc7f841d7f05e0f5baad14ec71277cd77f1
                        │      │                   b7eaf95a1a4 
                        │      ├ Title           : crypto/x509: Panic in name constraint checking for malformed
                        │      │                    certificates in crypto/x509 
                        │      ├ Description     : Certificate verification can panic when a certificate in the
                        │      │                    chain has an empty DNS name and another certificate in the
                        │      │                   chain has excluded name constraints. This can crash programs
                        │      │                    that are either directly verifying X.509 certificate
                        │      │                   chains, or those that use TLS. 
                        │      ├ Severity        : LOW 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ azure  : 2 
                        │      │                  ├ bitnami: 2 
                        │      │                  ╰ redhat : 1 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 5.9 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:L 
                        │      │                            ╰ V3Score : 3.7 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-27138 
                        │      │                  ├ [1]: https://go.dev/cl/752183 
                        │      │                  ├ [2]: https://go.dev/issue/77953 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/EdhZqrQ9
                        │      │                  │      8hk 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-27138 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-4600 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-27138 
                        │      ├ PublishedDate   : 2026-03-06T22:16:00.963Z 
                        │      ╰ LastModifiedDate: 2026-04-21T14:39:28.073Z 
                        ╰ [20] ╭ VulnerabilityID : CVE-2026-27139 
                               ├ VendorIDs        ─ [0]: GO-2026-4602 
                               ├ PkgID           : stdlib@v1.26.0 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.0 
                               │                  ╰ UID : 8d6cb282fd98a7ac 
                               ├ InstalledVersion: v1.26.0 
                               ├ FixedVersion    : 1.25.8, 1.26.1 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:d917dad6a375cc8ede97c53b14ae842416b6890baaf1
                               │                  │         e604d470cc284fe84f9a 
                               │                  ╰ DiffID: sha256:fbdbdf9563ccca83c63d36aa5df8acff2bc2e0ffd919
                               │                            c9a6ba0df01bfc18beca 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27139 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:5e6cb1470305416b04226bb8fad09161bae43bdaccdde311b8f48
                               │                   9a20d75e64a 
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
                               ╰ LastModifiedDate: 2026-04-21T14:32:36.317Z 
```

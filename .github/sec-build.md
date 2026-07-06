```yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.24.0) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target         : Java 
│     ├ Class          : lang-pkgs 
│     ├ Type           : jar 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-54512 
│                       │     ├ VendorIDs        ─ [0]: GHSA-j3rv-43j4-c7qm 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : bdedb7f4f2b3e6f5 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.18.8, 3.1.4, 2.21.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54512 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:b0fa4b8dcd75da601005560742ce6b760145554c8ae4322116ef0d
│                       │     │                   07dd25ef52 
│                       │     ├ Title           : jackson-databind: jackson-databind: Arbitrary code execution
│                       │     │                   via PolymorphicTypeValidator bypass 
│                       │     ├ Description     : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionality and tree-model for Jackson Data Processor. From
│                       │     │                    2.10.0 until 2.18.8, 2.21.4, and 3.1.4, jackson-databind's
│                       │     │                   PolymorphicTypeValidator (PTV) is the primary safety
│                       │     │                   mechanism guarding polymorphic deserialization. When
│                       │     │                   polymorphic typing is enabled and a type identifier contains
│                       │     │                   generic parameters (i.e. the type ID string contains <),
│                       │     │                   DatabindContext._resolveAndValidateGeneric() validates only
│                       │     │                   the raw container class name (the substring before <) against
│                       │     │                    the configured PTV. If the container type is approved, the
│                       │     │                   method parses the full canonical type string via
│                       │     │                   TypeFactory.constructFromCanonical() and returns the fully
│                       │     │                   parameterized type without ever validating the nested type
│                       │     │                   arguments against the PTV. The nested type arguments are then
│                       │     │                    resolved, instantiated, and populated as beans during
│                       │     │                   deserialization. An attacker who controls the type ID can
│                       │     │                   therefore place a denied class as a generic type parameter of
│                       │     │                    an allowed container — for example
│                       │     │                   java.util.ArrayList<com.evil.Gadget> when only
│                       │     │                   java.util.ArrayList is allow-listed. The container passes the
│                       │     │                    PTV check; com.evil.Gadget is loaded via Class.forName(name,
│                       │     │                    true, loader), instantiated, and its properties are set from
│                       │     │                    attacker-controlled JSON. This completely bypasses an
│                       │     │                   explicitly configured PTV allow-list. This vulnerability is
│                       │     │                   fixed in 2.18.8, 2.21.4, and 3.1.4. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ╭ [0]: CWE-184 
│                       │     │                  ╰ [1]: CWE-502 
│                       │     ├ VendorSeverity   ╭ ghsa  : 3 
│                       │     │                  ╰ redhat: 3 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/
│                       │     │                  │        │           A:H 
│                       │     │                  │        ╰ V3Score : 8.1 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 8.1 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54512 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/43
│                       │     │                  │      4d6c511de7fdd9872f29157aafb6162d12d8d5 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/issues/5988 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                  │      advisories/GHSA-j3rv-43j4-c7qm 
│                       │     │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-54512 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-54512 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.203Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T21:01:36.47Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-54513 
│                       │     ├ VendorIDs        ─ [0]: GHSA-rmj7-2vxq-3g9f 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : bdedb7f4f2b3e6f5 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.18.8, 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54513 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:00bf54a0e20875f7e04d671c1365fc94606003cf09abb25ca03594
│                       │     │                   9e5d9404ab 
│                       │     ├ Title           : jackson-databind: Jackson-databind: Security bypass allows
│                       │     │                   arbitrary code execution 
│                       │     ├ Description     : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionality and tree-model for Jackson Data Processor. From
│                       │     │                    2.10.0 until 2.18.8, 2.21.4, and 3.1.4,
│                       │     │                   BasicPolymorphicTypeValidator.Builder.allowIfSubTypeIsArray()
│                       │     │                    allowlists any array type based only on clazz.isArray(),
│                       │     │                   without validating the array's component (element) type
│                       │     │                   against the configured allowlist. A PTV built with
│                       │     │                   allowIfSubTypeIsArray() plus an explicit concrete-type
│                       │     │                   allowlist therefore still permits EvilType[] even though
│                       │     │                   EvilType is not allowlisted. When Jackson deserializes the
│                       │     │                   elements and no per-element type IDs are present, it
│                       │     │                   instantiates the component type directly with no further PTV
│                       │     │                   check, bypassing the allowlist. This vulnerability is fixed
│                       │     │                   in 2.18.8, 2.21.4, and 3.1.4. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-184 
│                       │     ├ VendorSeverity   ╭ ghsa  : 3 
│                       │     │                  ╰ redhat: 3 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/
│                       │     │                  │        │           A:H 
│                       │     │                  │        ╰ V3Score : 8.1 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/
│                       │     │                           │           A:H 
│                       │     │                           ╰ V3Score : 8.1 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-54513 
│                       │     │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=2492010 
│                       │     │                  ├ [2] : https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [3] : https://github.com/FasterXML/jackson-databind/commit/0
│                       │     │                  │       1d1692c8d0ed03e51a0e3c4f8a9e6908e4931e5 
│                       │     │                  ├ [4] : https://github.com/FasterXML/jackson-databind/commit/2
│                       │     │                  │       4529da29fdf46ff94ca38de9ebf31cd188f5e8e 
│                       │     │                  ├ [5] : https://github.com/FasterXML/jackson-databind/issues/5
│                       │     │                  │       981 
│                       │     │                  ├ [6] : https://github.com/FasterXML/jackson-databind/issues/5
│                       │     │                  │       983 
│                       │     │                  ├ [7] : https://github.com/FasterXML/jackson-databind/pull/5984 
│                       │     │                  ├ [8] : https://github.com/FasterXML/jackson-databind/security
│                       │     │                  │       /advisories/GHSA-rmj7-2vxq-3g9f 
│                       │     │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-54513 
│                       │     │                  ├ [10]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-54513.json 
│                       │     │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-54513 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.333Z 
│                       │     ╰ LastModifiedDate: 2026-07-03T13:17:29.627Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-54514 
│                       │     ├ VendorIDs        ─ [0]: GHSA-hgj6-7826-r7m5 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : bdedb7f4f2b3e6f5 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.18.8, 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54514 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:f1bc7361a45ab233bfa8fccc4f494df61edcc83a3c357e13c57b8c
│                       │     │                   c686d8f629 
│                       │     ├ Title           : jackson-databind: jackson-databind: Information Disclosure
│                       │     │                   via Eager DNS Resolution 
│                       │     ├ Description     : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionality and tree-model for Jackson Data Processor. From
│                       │     │                    2.0.0 until 2.18.8, 2.21.4, and 3.1.4,
│                       │     │                   JDKFromStringDeserializer constructed InetSocketAddress with
│                       │     │                   new InetSocketAddress(host, port), which performs eager DNS
│                       │     │                   name resolution for hostname inputs at deserialization time.
│                       │     │                   An application that binds untrusted JSON into a type
│                       │     │                   containing an InetSocketAddress field issues an
│                       │     │                   attacker-chosen DNS query during readValue, before any
│                       │     │                   application-level validation or connect logic. The fix uses
│                       │     │                   InetSocketAddress.createUnresolved(host, port), deferring DNS
│                       │     │                    to an explicit connect. This vulnerability is fixed in
│                       │     │                   2.18.8, 2.21.4, and 3.1.4. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-918 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54514 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/1f
│                       │     │                  │      5a1037b1e9e05920e755cb35f198bcd46667e4 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/pull/5951 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                  │      advisories/GHSA-hgj6-7826-r7m5 
│                       │     │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-54514 
│                       │     │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-54514 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.467Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T20:55:09.61Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-54515 
│                       │     ├ VendorIDs        ─ [0]: GHSA-5jmj-h7xm-6q6v 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : bdedb7f4f2b3e6f5 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 3.1.4, 2.18.9, 2.21.5, 2.22.1 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54515 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:e89e5edc3ebd3514e86f94e21b3525a8fd4ae670770d81b2119a3e
│                       │     │                   45ab573aa4 
│                       │     ├ Title           : jackson-databind: jackson-databind: Ignored properties can be
│                       │     │                    unexpectedly modified 
│                       │     ├ Description     : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionality and tree-model for Jackson Data Processor. From
│                       │     │                    2.8.0 until 2.18.9, 2.21.5, and 3.1.4, in
│                       │     │                   BeanDeserializerBase.createContextual(), per-property
│                       │     │                   @JsonIgnoreProperties exclusions are applied by
│                       │     │                   _handleByNameInclusion(), producing a contextual deserializer
│                       │     │                    whose BeanPropertyMap has the ignored properties removed.
│                       │     │                   The subsequent per-property case-insensitivity block
│                       │     │                   (triggered by
│                       │     │                   @JsonFormat(ACCEPT_CASE_INSENSITIVE_PROPERTIES)) rebuilds
│                       │     │                   from this._beanProperties (the original, unfiltered map)
│                       │     │                   instead of contextual._beanProperties, then overwrites the
│                       │     │                   filtered map — restoring every property
│                       │     │                   _handleByNameInclusion had just removed. The ignored property
│                       │     │                    becomes writable again. This vulnerability is fixed in
│                       │     │                   2.18.9, 2.21.5, and 3.1.4. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-915 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54515 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/0e
│                       │     │                  │      1b0b211f7a53baa62ba2f4c9bd006c7bf4d5fa 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/issues/5962 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/issues/5964 
│                       │     │                  ├ [5]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                  │      advisories/GHSA-5jmj-h7xm-6q6v 
│                       │     │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-54515 
│                       │     │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-54515 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.597Z 
│                       │     ╰ LastModifiedDate: 2026-06-29T13:38:59.057Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-54516 
│                       │     ├ VendorIDs        ─ [0]: GHSA-9fxm-vc8v-hj55 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : bdedb7f4f2b3e6f5 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54516 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:ccb557326790962c553db4f7ed5b74e27ff63b13a0b3e735ce927c
│                       │     │                   201ac4e8ef 
│                       │     ├ Title           : jackson-databind: jackson-databind: Security bypass due to
│                       │     │                   improper handling of renamed properties 
│                       │     ├ Description     : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionality and tree-model for Jackson Data Processor. From
│                       │     │                    2.21.0 until 2.21.4 and 3.1.4,
│                       │     │                   POJOPropertiesCollector._renameProperties() allows a property
│                       │     │                    with @JsonProperty("renamed") on the getter and @JsonIgnore
│                       │     │                   on the setter to be renamed rather than dropped. With
│                       │     │                   MapperFeature.INFER_PROPERTY_MUTATORS enabled (default), the
│                       │     │                   private backing field is retained; during deserialization
│                       │     │                   BeanDeserializerFactory.addBeanProps() sees hasField()==true,
│                       │     │                    builds a FieldProperty, and makes the backing field
│                       │     │                   writable. An attacker supplying the renamed JSON key writes
│                       │     │                   the backing field directly, bypassing the @JsonIgnore on the
│                       │     │                   setter. This vulnerability is fixed in 3.1.4. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-915 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54516 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/c3
│                       │     │                  │      d56dd25d52319828147c5b9aeabf2d485c250a 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/commit/e8
│                       │     │                  │      8cb17006b6af4883b973058f0bb6486e5074af 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/pull/5967 
│                       │     │                  ├ [5]: https://github.com/FasterXML/jackson-databind/pull/5968 
│                       │     │                  ├ [6]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                  │      advisories/GHSA-9fxm-vc8v-hj55 
│                       │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-54516 
│                       │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-54516 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.723Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T20:52:12.103Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-54517 
│                       │     ├ VendorIDs        ─ [0]: GHSA-5hh8-q8hv-fr38 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : bdedb7f4f2b3e6f5 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54517 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:992e4509fc1d10a308211ee0b9bee93896e31a242f9be5a363b81c
│                       │     │                   e20c547831 
│                       │     ├ Title           : jackson-databind: jackson-databind: Information disclosure
│                       │     │                   via improper JsonView filter application 
│                       │     ├ Description     : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionality and tree-model for Jackson Data Processor. From
│                       │     │                    2.21.0 until 2.21.4 and 3.1.4, in
│                       │     │                   BeanDeserializer._deserializeUsingPropertyBased, the
│                       │     │                   active-view (@JsonView) filter was applied only to creator
│                       │     │                   properties; the regular property-buffering branch performed
│                       │     │                   no prop.visibleInView(activeView) check. A change making
│                       │     │                   SetterlessProperty.isMerging() return true routed setterless
│                       │     │                   Collection/Map properties through this unguarded path, so a
│                       │     │                   setterless collection annotated with a restricted @JsonView
│                       │     │                   is populated from attacker JSON even when the active view
│                       │     │                   excludes it. This vulnerability is fixed in 2.21.4 and
│                       │     │                   3.1.4. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-863 
│                       │     ├ VendorSeverity   ╭ ghsa  : 2 
│                       │     │                  ╰ redhat: 2 
│                       │     ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/
│                       │     │                  │        │           A:N 
│                       │     │                  │        ╰ V3Score : 5.3 
│                       │     │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/
│                       │     │                           │           A:N 
│                       │     │                           ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54517 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/5b
│                       │     │                  │      f23edb4221f7dd2ec8e71ff6d26c61640f261d 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/commit/94
│                       │     │                  │      c5d215b3af1505098c686405d9641f041a9962 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/pull/5969 
│                       │     │                  ├ [5]: https://github.com/FasterXML/jackson-databind/pull/5970 
│                       │     │                  ├ [6]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                  │      advisories/GHSA-5hh8-q8hv-fr38 
│                       │     │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-54517 
│                       │     │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-54517 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.853Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T20:51:09.987Z 
│                       ╰ [6] ╭ VulnerabilityID : CVE-2026-54518 
│                             ├ VendorIDs        ─ [0]: GHSA-rcqc-6cw3-h962 
│                             ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                             ├ PkgPath         : openaf/openaf.jar 
│                             ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                             │                  │       2.21.3 
│                             │                  ╰ UID : bdedb7f4f2b3e6f5 
│                             ├ InstalledVersion: 2.21.3 
│                             ├ FixedVersion    : 2.21.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                             │                  │         2a20dd0e2b3b62af5b6 
│                             │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                             │                            279df2dec37df06a5a9 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54518 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:34d74862f6e270032fbdef5a08f2dc5e8ad58d03fd51750f2c2036
│                             │                   979b85e24b 
│                             ├ Title           : jackson-databind: jackson-databind: Information disclosure
│                             │                   and data manipulation via view-based access control bypass 
│                             ├ Description     : jackson-databind contains the general-purpose data-binding
│                             │                   functionality and tree-model for Jackson Data Processor. From
│                             │                    2.21.0 until 2.21.4 and 3.1.4,
│                             │                   UnwrappedPropertyHandler.processUnwrappedCreatorProperties()
│                             │                   replays buffered JSON into creator parameters but never
│                             │                   consults prop.visibleInView(activeView). The normal
│                             │                   property-based creator path gates creator properties on the
│                             │                   active view, but this unwrapped-creator replay path bypasses
│                             │                   that check, so a constructor parameter annotated with both
│                             │                   @JsonView(AdminView.class) and @JsonUnwrapped is populated
│                             │                   from attacker JSON even when a more restrictive view is
│                             │                   active. This vulnerability is fixed in 2.21.4 and 3.1.4. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-863 
│                             ├ VendorSeverity   ╭ ghsa  : 2 
│                             │                  ╰ redhat: 2 
│                             ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/
│                             │                  │        │           A:N 
│                             │                  │        ╰ V3Score : 6.5 
│                             │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/
│                             │                           │           A:N 
│                             │                           ╰ V3Score : 6.5 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54518 
│                             │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                             │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/72
│                             │                  │      1fa07ebbd4aab4a659a1a68940878315c3e341 
│                             │                  ├ [3]: https://github.com/FasterXML/jackson-databind/commit/d6
│                             │                  │      33bc038f200c1397c07f1a2b46f58e72c91eea 
│                             │                  ├ [4]: https://github.com/FasterXML/jackson-databind/pull/5971 
│                             │                  ├ [5]: https://github.com/FasterXML/jackson-databind/pull/5973 
│                             │                  ├ [6]: https://github.com/FasterXML/jackson-databind/security/
│                             │                  │      advisories/GHSA-rcqc-6cw3-h962 
│                             │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-54518 
│                             │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-54518 
│                             ├ PublishedDate   : 2026-06-23T22:16:32.073Z 
│                             ╰ LastModifiedDate: 2026-06-27T20:49:30.977Z 
├ [2] ╭ Target  : Node.js 
│     ├ Class   : lang-pkgs 
│     ├ Type    : node-pkg 
│     ╰ Packages 
├ [3] ╭ Target  : Python 
│     ├ Class   : lang-pkgs 
│     ├ Type    : python-pkg 
│     ╰ Packages 
├ [4] ╭ Target  : usr/bin/prometheus 
│     ├ Class   : lang-pkgs 
│     ├ Type    : gobinary 
│     ╰ Packages 
├ [5] ╭ Target  : usr/bin/promtool 
│     ├ Class   : lang-pkgs 
│     ├ Type    : gobinary 
│     ╰ Packages 
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
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:2ed128b94862112724d6a7403edf018bcaafd6f454c661e0d5d97e
│                       │     │                   fe0f445fc2 
│                       │     ├ Title           : grafana/tempo: Tempo: Denial of Service via large queries 
│                       │     ├ Description     : Tempo queries with large limits can cause large memory
│                       │     │                   allocations which can impact the availability of the service,
│                       │     │                    depending on its deployment strategy.
│                       │     │                   
│                       │     │                   Mitigation can be done by setting max_result_limit in the
│                       │     │                   search config, e.g. to 262144 (2^18). 
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
│                       │     ╰ LastModifiedDate: 2026-06-30T03:17:24.707Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:abb801229a1635d7be6614fcbc80af76289f18747c6c635bfc0693
│                       │     │                   68cb92adcb 
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
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-48096 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:a6b0a3ab06168b6a892343088fb2b40eed9c81c80a37a795dc7f56
│                       │     │                   4b8c7882c5 
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
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55689 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Fingerprint     : sha256:378676f604a3b5e0c9ff3c9b0e5aeee86da1b044593009ff84fecc
│                       │     │                   182875bc25 
│                       │     ├ Title           : OpenFGA: OIDC audience validation skipped when
│                       │     │                   --authn-oidc-audience is unset 
│                       │     ├ Description     : ## Description
│                       │     │                   
│                       │     │                   OpenFGA's OIDC authenticator skipped JWT audience (`aud`)
│                       │     │                   validation when no audience was configured.
│                       │     │                   In deployments where one identity provider issues tokens for
│                       │     │                   multiple services,
│                       │     │                   a token minted for an unrelated service could authenticate to
│                       │     │                    OpenFGA.
│                       │     │                   ## Preconditions
│                       │     │                   This applies if the following preconditions are met:
│                       │     │                   1. You run OpenFGA with `authn.method` set to `oidc`.
│                       │     │                   2. You configured `authn.oidc.issuer` but did **not** set
│                       │     │                      `authn.oidc.audience` (`--authn-oidc-audience` /
│                       │     │                   `OPENFGA_AUTHN_OIDC_AUDIENCE`).
│                       │     │                   ## Fix
│                       │     │                   Upgrade to OpenFGA 1.18.0 or greater. OpenFGA now refuses to
│                       │     │                   start in `oidc`
│                       │     │                   mode unless both `authn.oidc.issuer` and
│                       │     │                   `authn.oidc.audience` are set, and the
│                       │     │                   `aud` claim is always validated.
│                       │     │                   ## Acknowledgements
│                       │     │                   OpenFGA would like to thank https://github.com/0xVijay for
│                       │     │                   the report. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N 
│                       │     │                         ╰ V3Score : 6.8 
│                       │     ╰ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │                        ╰ [1]: https://github.com/openfga/openfga/security/advisories/
│                       │                               GHSA-hcxc-wf8j-23hv 
│                       ╰ [4] ╭ VulnerabilityID : CVE-2026-55170 
│                             ├ VendorIDs        ─ [0]: GHSA-cf98-j28v-49v6 
│                             ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                             ├ PkgName         : github.com/openfga/openfga 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                             │                  ╰ UID : d9f7c327b4e77cd7 
│                             ├ InstalledVersion: v1.14.2 
│                             ├ FixedVersion    : 1.18.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                             │                  │         2a20dd0e2b3b62af5b6 
│                             │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                             │                            279df2dec37df06a5a9 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55170 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Fingerprint     : sha256:98ea52bb86198f45936ef69ed57850a4a4ccac2740780eae2e05cc
│                             │                   b8c55adfea 
│                             ├ Title           : OpenFGA Improper Policy Enforcement 
│                             ├ Description     : ## Description
│                             │                   
│                             │                   In OpenFGA, when MySQL is being used as the datastore, two
│                             │                   distinct check requests can return the same response.
│                             │                   ## Preconditions
│                             │                   This applies if the following preconditions are met:
│                             │                   1. You run OpenFGA with MySQL as the datastore
│                             │                   2. Your authorization decisions rely on case-sensitive user
│                             │                   strings.
│                             │                   ## Fix
│                             │                   Upgrade to OpenFGA 1.18.0 or greater.
│                             │                   ## Acknowledgements
│                             │                   OpenFGA would like to thank @sahajamoth for the detailed
│                             │                   report. 
│                             ├ Severity        : LOW 
│                             ├ VendorSeverity   ─ ghsa: 1 
│                             ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI:
│                             │                         │            L/VA:N/SC:L/SI:L/SA:N 
│                             │                         ╰ V40Score : 2.1 
│                             ╰ References       ╭ [0]: https://github.com/openfga/openfga 
│                                                ╰ [1]: https://github.com/openfga/openfga/security/advisories/
│                                                       GHSA-cf98-j28v-49v6 
├ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
│     │                  rce_linux_amd64 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2026-27145 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:811d028690ca93e2a52f45b5fa9a352f0b0c15768890b654e6420b
│                       │     │                   613c814144 
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
│                       │     ├ VendorSeverity   ╭ amazon : 3 
│                       │     │                  ├ bitnami: 2 
│                       │     │                  ╰ redhat : 3 
│                       │     ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L
│                       │     │                  │         │           /A:H 
│                       │     │                  │         ╰ V3Score : 6.5 
│                       │     │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:33574 
│                       │     │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:34357 
│                       │     │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:34359 
│                       │     │                  ├ [3] : https://access.redhat.com/security/cve/CVE-2026-27145 
│                       │     │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
│                       │     │                  ├ [5] : https://go.dev/cl/783621 
│                       │     │                  ├ [6] : https://go.dev/issue/79694 
│                       │     │                  ├ [7] : https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │     │                  │       cKw 
│                       │     │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │     │                  ├ [9] : https://pkg.go.dev/vuln/GO-2026-5037 
│                       │     │                  ├ [10]: https://security.access.redhat.com/data/csaf/v2/vex/20
│                       │     │                  │       26/cve-2026-27145.json 
│                       │     │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │     ╰ LastModifiedDate: 2026-07-02T12:16:59.51Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-42504 
│                       │     ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │     ├ PkgID           : stdlib@v1.26.3 
│                       │     ├ PkgName         : stdlib 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │     │                  ╰ UID : f77aad5d3fa73e61 
│                       │     ├ InstalledVersion: v1.26.3 
│                       │     ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                       │     │                  │         2a20dd0e2b3b62af5b6 
│                       │     │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                       │     │                            279df2dec37df06a5a9 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │     ├ DataSource       ╭ ID  : govulndb 
│                       │     │                  ├ Name: The Go Vulnerability Database 
│                       │     │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │     ├ Fingerprint     : sha256:6761c511be6daf769872c638ba4c254c862601830872056f7e7aa9
│                       │     │                   bc611864fc 
│                       │     ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid enc ... 
│                       │     ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │     │                   invalid encoded-words can consume excessive CPU. 
│                       │     ├ Severity        : HIGH 
│                       │     ├ CweIDs           ─ [0]: CWE-407 
│                       │     ├ VendorSeverity   ╭ amazon : 3 
│                       │     │                  ├ azure  : 3 
│                       │     │                  ╰ bitnami: 3 
│                       │     ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │     │                            │           /A:H 
│                       │     │                            ╰ V3Score : 7.5 
│                       │     ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │     │                  ├ [1]: https://go.dev/issue/79217 
│                       │     │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcBcKw 
│                       │     │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │     │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │     ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │     ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
│                       ╰ [2] ╭ VulnerabilityID : CVE-2026-42507 
│                             ├ VendorIDs        ─ [0]: GO-2026-5039 
│                             ├ PkgID           : stdlib@v1.26.3 
│                             ├ PkgName         : stdlib 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                             │                  ╰ UID : f77aad5d3fa73e61 
│                             ├ InstalledVersion: v1.26.3 
│                             ├ FixedVersion    : 1.25.11, 1.26.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e5
│                             │                  │         2a20dd0e2b3b62af5b6 
│                             │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0cb
│                             │                            279df2dec37df06a5a9 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                             ├ DataSource       ╭ ID  : govulndb 
│                             │                  ├ Name: The Go Vulnerability Database 
│                             │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                             ├ Fingerprint     : sha256:62ac3832774dfa1e17e85f18d24d1523b755067aeb47acad792c19
│                             │                   5b4021f523 
│                             ├ Title           : net/textproto: golang: Golang net/textproto: Misleading error
│                             │                    messages via input injection 
│                             ├ Description     : When returning errors, functions in the net/textproto package
│                             │                    would include its input as part of the error. This might
│                             │                   allow an attacker to inject misleading content to errors that
│                             │                    are printed or logged. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ╭ alma       : 2 
│                             │                  ├ amazon     : 3 
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
│                             │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:29981 
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
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-29181 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:79037134791cfa95f1a959d022738a0a629a97ca1571aba2b59d2
                        │      │                   1f3d6a5c3c1 
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
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39883 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Fingerprint     : sha256:8b4b847b33479b5e78d7e641d59db9fbc7223e149b557173925e4
                        │      │                   67dbd803d37 
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
                        │      ├ References       ╭ [0]: http://github.com/open-telemetry/opentelemetry-go/rele
                        │      │                  │      ases/tag/v1.43.0 
                        │      │                  ├ [1]: https://access.redhat.com/errata/RHSA-2026:26254 
                        │      │                  ├ [2]: https://access.redhat.com/errata/RHSA-2026:26257 
                        │      │                  ├ [3]: https://access.redhat.com/security/cve/CVE-2026-39883 
                        │      │                  ├ [4]: https://bugzilla.redhat.com/show_bug.cgi?id=2456718 
                        │      │                  ├ [5]: https://github.com/open-telemetry/opentelemetry-go 
                        │      │                  ├ [6]: https://github.com/open-telemetry/opentelemetry-go/sec
                        │      │                  │      urity/advisories/GHSA-hfvc-g4fc-pqhx 
                        │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-39883 
                        │      │                  ├ [8]: https://security.access.redhat.com/data/csaf/v2/vex/20
                        │      │                  │      26/cve-2026-39883.json 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39883 
                        │      ├ PublishedDate   : 2026-04-08T21:17:00.697Z 
                        │      ╰ LastModifiedDate: 2026-06-30T03:19:07.957Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-25681 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5029 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cbc8195e03f2d391bbf12d578e04bc40eb120c1b607266cc40bbb
                        │      │                   922a0d1ef01 
                        │      ├ Title           : golang.org/x/net/html: golang.org/x/net/html: Arbitrary code
                        │      │                    execution via Cross-Site Scripting 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1021 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-25681 
                        │      │                  ├ [1]: https://go.dev/cl/781703 
                        │      │                  ├ [2]: https://go.dev/issue/79574 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-25681 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5029 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-25681 
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
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:38d318a1cb09d0c14a0f883e7e75c8676f18cf69e60edb7126e0c
                        │      │                   9a8528e633c 
                        │      ├ Title           : golang.org/x/net/html: golang: golang.org/x/net/html:
                        │      │                   Cross-Site Scripting via HTML parsing bypass 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1021 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-27136 
                        │      │                  ├ [1]: https://go.dev/cl/781685 
                        │      │                  ├ [2]: https://go.dev/issue/79575 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-27136 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5030 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-27136 
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
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4ca902b9f8f76fc410fab2c154d893f25917c3f11ca309c0b6e26
                        │      │                   0ab70a5f282 
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
                        │      │                  ├ [7] : https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [9] : https://github.com/golang/go/issues/78476 
                        │      │                  ├ [10]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [11]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [12]: https://go.dev/cl/761581 
                        │      │                  ├ [13]: https://go.dev/cl/761640 
                        │      │                  ├ [14]: https://go.dev/issue/78476 
                        │      │                  ├ [15]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [16]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [17]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [18]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [19]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [20]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [21]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [22]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [23]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [24]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [25]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:06.34Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:48a34cb45de2c0a3a1d2388e4f803db7e2ce0d811f6e4384164fa
                        │      │                   961ce7d4d03 
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
                        │      │                  ├ [20]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [21]: https://bugzilla.redhat.com/2480756 
                        │      │                  ├ [22]: https://bugzilla.redhat.com/show_bug.cgi?id=2480756 
                        │      │                  ├ [23]: https://errata.almalinux.org/9/ALSA-2026-30854.html 
                        │      │                  ├ [24]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [25]: https://go.dev/cl/767220 
                        │      │                  ├ [26]: https://go.dev/issue/78760 
                        │      │                  ├ [27]: https://groups.google.com/g/golang-announce/c/iI-mYSI
                        │      │                  │       0lu8 
                        │      │                  ├ [28]: https://linux.oracle.com/cve/CVE-2026-39821.html 
                        │      │                  ├ [29]: https://linux.oracle.com/errata/ELSA-2026-30854.html 
                        │      │                  ├ [30]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [31]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [32]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39821.json 
                        │      │                  ├ [33]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:12.24Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-42502 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5027 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:b80be72aea6dd5d062f904a9845162abf86ccccf22ff4a314eab3
                        │      │                   eafe9ca6cdf 
                        │      ├ Title           : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result  ... 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-1021 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ azure : 2 
                        │      ├ References       ╭ [0]: https://go.dev/cl/781701 
                        │      │                  ├ [1]: https://go.dev/issue/79572 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42502 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5027 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.587Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.593Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:6e128060641c11f9c9ef663ed01a5fda7d9bb9ba2dec6b7ef9305
                        │      │                   378989f0f51 
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
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-42506 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5025 
                        │      ├ PkgID           : golang.org/x/net@v0.49.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.49.0 
                        │      │                  ╰ UID : d9a61092434f99e5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:ca43fcff00c3046dc1e91429e821d183295564ba5331018a0523b
                        │      │                   848cc49c8db 
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
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-39824 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5024 
                        │      ├ PkgID           : golang.org/x/sys@v0.40.0 
                        │      ├ PkgName         : golang.org/x/sys 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/sys@v0.40.0 
                        │      │                  ╰ UID : 9084712f03f133bd 
                        │      ├ InstalledVersion: v0.40.0 
                        │      ├ FixedVersion    : 0.44.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:81d6ad7eb1b3ec3b6e596327a61e87f3a15fbf47bfa0fb51b6d1b
                        │      │                   ab9420491f0 
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
                        ├ [10] ╭ VulnerabilityID : CVE-2026-25679 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4601 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.8, 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25679 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:b36fb8e49fc755cd29641c2a9008686c4869af42c8a1a6d08dae6
                        │      │                   f9448c6f22f 
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
                        │      │                  ├ [125]: https://access.redhat.com/errata/RHSA-2026:29035 
                        │      │                  ├ [126]: https://access.redhat.com/errata/RHSA-2026:29195 
                        │      │                  ├ [127]: https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [128]: https://access.redhat.com/errata/RHSA-2026:29702 
                        │      │                  ├ [129]: https://access.redhat.com/errata/RHSA-2026:29703 
                        │      │                  ├ [130]: https://access.redhat.com/errata/RHSA-2026:29854 
                        │      │                  ├ [131]: https://access.redhat.com/errata/RHSA-2026:33722 
                        │      │                  ├ [132]: https://access.redhat.com/errata/RHSA-2026:34365 
                        │      │                  ├ [133]: https://access.redhat.com/errata/RHSA-2026:5110 
                        │      │                  ├ [134]: https://access.redhat.com/errata/RHSA-2026:5549 
                        │      │                  ├ [135]: https://access.redhat.com/errata/RHSA-2026:5941 
                        │      │                  ├ [136]: https://access.redhat.com/errata/RHSA-2026:5942 
                        │      │                  ├ [137]: https://access.redhat.com/errata/RHSA-2026:5943 
                        │      │                  ├ [138]: https://access.redhat.com/errata/RHSA-2026:5944 
                        │      │                  ├ [139]: https://access.redhat.com/errata/RHSA-2026:6341 
                        │      │                  ├ [140]: https://access.redhat.com/errata/RHSA-2026:6344 
                        │      │                  ├ [141]: https://access.redhat.com/errata/RHSA-2026:6382 
                        │      │                  ├ [142]: https://access.redhat.com/errata/RHSA-2026:6383 
                        │      │                  ├ [143]: https://access.redhat.com/errata/RHSA-2026:6388 
                        │      │                  ├ [144]: https://access.redhat.com/errata/RHSA-2026:6564 
                        │      │                  ├ [145]: https://access.redhat.com/errata/RHSA-2026:6720 
                        │      │                  ├ [146]: https://access.redhat.com/errata/RHSA-2026:6802 
                        │      │                  ├ [147]: https://access.redhat.com/errata/RHSA-2026:6949 
                        │      │                  ├ [148]: https://access.redhat.com/errata/RHSA-2026:7005 
                        │      │                  ├ [149]: https://access.redhat.com/errata/RHSA-2026:7009 
                        │      │                  ├ [150]: https://access.redhat.com/errata/RHSA-2026:7011 
                        │      │                  ├ [151]: https://access.redhat.com/errata/RHSA-2026:7259 
                        │      │                  ├ [152]: https://access.redhat.com/errata/RHSA-2026:7291 
                        │      │                  ├ [153]: https://access.redhat.com/errata/RHSA-2026:7315 
                        │      │                  ├ [154]: https://access.redhat.com/errata/RHSA-2026:7328 
                        │      │                  ├ [155]: https://access.redhat.com/errata/RHSA-2026:7385 
                        │      │                  ├ [156]: https://access.redhat.com/errata/RHSA-2026:7665 
                        │      │                  ├ [157]: https://access.redhat.com/errata/RHSA-2026:7669 
                        │      │                  ├ [158]: https://access.redhat.com/errata/RHSA-2026:7674 
                        │      │                  ├ [159]: https://access.redhat.com/errata/RHSA-2026:7833 
                        │      │                  ├ [160]: https://access.redhat.com/errata/RHSA-2026:7834 
                        │      │                  ├ [161]: https://access.redhat.com/errata/RHSA-2026:7876 
                        │      │                  ├ [162]: https://access.redhat.com/errata/RHSA-2026:7877 
                        │      │                  ├ [163]: https://access.redhat.com/errata/RHSA-2026:7878 
                        │      │                  ├ [164]: https://access.redhat.com/errata/RHSA-2026:7879 
                        │      │                  ├ [165]: https://access.redhat.com/errata/RHSA-2026:7883 
                        │      │                  ├ [166]: https://access.redhat.com/errata/RHSA-2026:7992 
                        │      │                  ├ [167]: https://access.redhat.com/errata/RHSA-2026:8151 
                        │      │                  ├ [168]: https://access.redhat.com/errata/RHSA-2026:8167 
                        │      │                  ├ [169]: https://access.redhat.com/errata/RHSA-2026:8314 
                        │      │                  ├ [170]: https://access.redhat.com/errata/RHSA-2026:8322 
                        │      │                  ├ [171]: https://access.redhat.com/errata/RHSA-2026:8324 
                        │      │                  ├ [172]: https://access.redhat.com/errata/RHSA-2026:8337 
                        │      │                  ├ [173]: https://access.redhat.com/errata/RHSA-2026:8338 
                        │      │                  ├ [174]: https://access.redhat.com/errata/RHSA-2026:8433 
                        │      │                  ├ [175]: https://access.redhat.com/errata/RHSA-2026:8434 
                        │      │                  ├ [176]: https://access.redhat.com/errata/RHSA-2026:8456 
                        │      │                  ├ [177]: https://access.redhat.com/errata/RHSA-2026:8483 
                        │      │                  ├ [178]: https://access.redhat.com/errata/RHSA-2026:8484 
                        │      │                  ├ [179]: https://access.redhat.com/errata/RHSA-2026:8490 
                        │      │                  ├ [180]: https://access.redhat.com/errata/RHSA-2026:8491 
                        │      │                  ├ [181]: https://access.redhat.com/errata/RHSA-2026:8493 
                        │      │                  ├ [182]: https://access.redhat.com/errata/RHSA-2026:8840 
                        │      │                  ├ [183]: https://access.redhat.com/errata/RHSA-2026:8841 
                        │      │                  ├ [184]: https://access.redhat.com/errata/RHSA-2026:8842 
                        │      │                  ├ [185]: https://access.redhat.com/errata/RHSA-2026:8845 
                        │      │                  ├ [186]: https://access.redhat.com/errata/RHSA-2026:8847 
                        │      │                  ├ [187]: https://access.redhat.com/errata/RHSA-2026:8848 
                        │      │                  ├ [188]: https://access.redhat.com/errata/RHSA-2026:8849 
                        │      │                  ├ [189]: https://access.redhat.com/errata/RHSA-2026:8851 
                        │      │                  ├ [190]: https://access.redhat.com/errata/RHSA-2026:8852 
                        │      │                  ├ [191]: https://access.redhat.com/errata/RHSA-2026:8853 
                        │      │                  ├ [192]: https://access.redhat.com/errata/RHSA-2026:8855 
                        │      │                  ├ [193]: https://access.redhat.com/errata/RHSA-2026:8856 
                        │      │                  ├ [194]: https://access.redhat.com/errata/RHSA-2026:8860 
                        │      │                  ├ [195]: https://access.redhat.com/errata/RHSA-2026:8877 
                        │      │                  ├ [196]: https://access.redhat.com/errata/RHSA-2026:8878 
                        │      │                  ├ [197]: https://access.redhat.com/errata/RHSA-2026:8879 
                        │      │                  ├ [198]: https://access.redhat.com/errata/RHSA-2026:8881 
                        │      │                  ├ [199]: https://access.redhat.com/errata/RHSA-2026:8882 
                        │      │                  ├ [200]: https://access.redhat.com/errata/RHSA-2026:8930 
                        │      │                  ├ [201]: https://access.redhat.com/errata/RHSA-2026:8931 
                        │      │                  ├ [202]: https://access.redhat.com/errata/RHSA-2026:8949 
                        │      │                  ├ [203]: https://access.redhat.com/errata/RHSA-2026:9043 
                        │      │                  ├ [204]: https://access.redhat.com/errata/RHSA-2026:9044 
                        │      │                  ├ [205]: https://access.redhat.com/errata/RHSA-2026:9052 
                        │      │                  ├ [206]: https://access.redhat.com/errata/RHSA-2026:9090 
                        │      │                  ├ [207]: https://access.redhat.com/errata/RHSA-2026:9093 
                        │      │                  ├ [208]: https://access.redhat.com/errata/RHSA-2026:9094 
                        │      │                  ├ [209]: https://access.redhat.com/errata/RHSA-2026:9097 
                        │      │                  ├ [210]: https://access.redhat.com/errata/RHSA-2026:9098 
                        │      │                  ├ [211]: https://access.redhat.com/errata/RHSA-2026:9108 
                        │      │                  ├ [212]: https://access.redhat.com/errata/RHSA-2026:9109 
                        │      │                  ├ [213]: https://access.redhat.com/errata/RHSA-2026:9385 
                        │      │                  ├ [214]: https://access.redhat.com/errata/RHSA-2026:9434 
                        │      │                  ├ [215]: https://access.redhat.com/errata/RHSA-2026:9435 
                        │      │                  ├ [216]: https://access.redhat.com/errata/RHSA-2026:9436 
                        │      │                  ├ [217]: https://access.redhat.com/errata/RHSA-2026:9439 
                        │      │                  ├ [218]: https://access.redhat.com/errata/RHSA-2026:9440 
                        │      │                  ├ [219]: https://access.redhat.com/errata/RHSA-2026:9448 
                        │      │                  ├ [220]: https://access.redhat.com/errata/RHSA-2026:9453 
                        │      │                  ├ [221]: https://access.redhat.com/errata/RHSA-2026:9461 
                        │      │                  ├ [222]: https://access.redhat.com/errata/RHSA-2026:9695 
                        │      │                  ├ [223]: https://access.redhat.com/errata/RHSA-2026:9742 
                        │      │                  ├ [224]: https://access.redhat.com/errata/RHSA-2026:9872 
                        │      │                  ├ [225]: https://access.redhat.com/security/cve/CVE-2026-25679 
                        │      │                  ├ [226]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [227]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [228]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [229]: https://errata.almalinux.org/9/ALSA-2026-9044.html 
                        │      │                  ├ [230]: https://errata.rockylinux.org/RLSA-2026:9044 
                        │      │                  ├ [231]: https://go.dev/cl/752180 
                        │      │                  ├ [232]: https://go.dev/issue/77578 
                        │      │                  ├ [233]: https://groups.google.com/g/golang-announce/c/EdhZqr
                        │      │                  │        Q98hk 
                        │      │                  ├ [234]: https://linux.oracle.com/cve/CVE-2026-25679.html 
                        │      │                  ├ [235]: https://linux.oracle.com/errata/ELSA-2026-9044.html 
                        │      │                  ├ [236]: https://nvd.nist.gov/vuln/detail/CVE-2026-25679 
                        │      │                  ├ [237]: https://pkg.go.dev/vuln/GO-2026-4601 
                        │      │                  ├ [238]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-25679.json 
                        │      │                  ╰ [239]: https://www.cve.org/CVERecord?id=CVE-2026-25679 
                        │      ├ PublishedDate   : 2026-03-06T22:16:00.72Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:16:57.677Z 
                        ├ [11] ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2d75824935da69fecefc996eaf42c97239007dfbab7ea4bcd2fe4
                        │      │                   238271077f5 
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
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ bitnami: 2 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           L/A:H 
                        │      │                  │         ╰ V3Score : 6.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:33574 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [3] : https://access.redhat.com/security/cve/CVE-2026-27145 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/show_bug.cgi?id=2484207 
                        │      │                  ├ [5] : https://go.dev/cl/783621 
                        │      │                  ├ [6] : https://go.dev/issue/79694 
                        │      │                  ├ [7] : https://groups.google.com/g/golang-announce/c/tKs3rmc
                        │      │                  │       BcKw 
                        │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ├ [9] : https://pkg.go.dev/vuln/GO-2026-5037 
                        │      │                  ├ [10]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-27145.json 
                        │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-27145 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:16:59.51Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-32280 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4947 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32280 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0eeb28baa3a87f43ea20cd8f7287558355f75329627ecc656f855
                        │      │                   8cdfceb1ec2 
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
                        │      │                  ├ [113]: https://access.redhat.com/errata/RHSA-2026:29035 
                        │      │                  ├ [114]: https://access.redhat.com/errata/RHSA-2026:29195 
                        │      │                  ├ [115]: https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [116]: https://access.redhat.com/errata/RHSA-2026:29702 
                        │      │                  ├ [117]: https://access.redhat.com/errata/RHSA-2026:29703 
                        │      │                  ├ [118]: https://access.redhat.com/errata/RHSA-2026:29854 
                        │      │                  ├ [119]: https://access.redhat.com/errata/RHSA-2026:33722 
                        │      │                  ├ [120]: https://access.redhat.com/errata/RHSA-2026:34192 
                        │      │                  ├ [121]: https://access.redhat.com/errata/RHSA-2026:34196 
                        │      │                  ├ [122]: https://access.redhat.com/errata/RHSA-2026:34197 
                        │      │                  ├ [123]: https://access.redhat.com/errata/RHSA-2026:34365 
                        │      │                  ├ [124]: https://access.redhat.com/errata/RHSA-2026:9385 
                        │      │                  ├ [125]: https://access.redhat.com/security/cve/CVE-2026-32280 
                        │      │                  ├ [126]: https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [127]: https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [128]: https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [129]: https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [130]: https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [131]: https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [132]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [133]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [134]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [135]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32280 
                        │      │                  ├ [136]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32281 
                        │      │                  ├ [137]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32283 
                        │      │                  ├ [138]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [139]: https://errata.rockylinux.org/RLSA-2026:29703 
                        │      │                  ├ [140]: https://go.dev/cl/758320 
                        │      │                  ├ [141]: https://go.dev/issue/78282 
                        │      │                  ├ [142]: https://groups.google.com/g/golang-announce/c/0uYbvb
                        │      │                  │        PZRWU 
                        │      │                  ├ [143]: https://linux.oracle.com/cve/CVE-2026-32280.html 
                        │      │                  ├ [144]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [145]: https://nvd.nist.gov/vuln/detail/CVE-2026-32280 
                        │      │                  ├ [146]: https://pkg.go.dev/vuln/GO-2026-4947 
                        │      │                  ├ [147]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-32280.json 
                        │      │                  ╰ [148]: https://www.cve.org/CVERecord?id=CVE-2026-32280 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.247Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:02.92Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-32281 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4946 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32281 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:01603940670d3c17b92e671eff98fa222cd3c9d9778d6aa461fa3
                        │      │                   c064fa03f54 
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
                        ├ [14] ╭ VulnerabilityID : CVE-2026-32283 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4870 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32283 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:047c4dfbfc4f9b0d2cad9c9d40f3e25f30f0c2a3e27e6ccc1de68
                        │      │                   b295675a5f3 
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
                        │      │                  ├ [90] : https://access.redhat.com/errata/RHSA-2026:7291 
                        │      │                  ├ [91] : https://access.redhat.com/errata/RHSA-2026:7385 
                        │      │                  ├ [92] : https://access.redhat.com/security/cve/CVE-2026-32283 
                        │      │                  ├ [93] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [94] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [95] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [96] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [97] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [98] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [99] : https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [100]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [101]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-25679 
                        │      │                  ├ [102]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32280 
                        │      │                  ├ [103]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32281 
                        │      │                  ├ [104]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2
                        │      │                  │        026-32283 
                        │      │                  ├ [105]: https://errata.almalinux.org/9/ALSA-2026-29703.html 
                        │      │                  ├ [106]: https://errata.rockylinux.org/RLSA-2026:29703 
                        │      │                  ├ [107]: https://go.dev/cl/763767 
                        │      │                  ├ [108]: https://go.dev/issue/78334 
                        │      │                  ├ [109]: https://groups.google.com/g/golang-announce/c/0uYbvb
                        │      │                  │        PZRWU 
                        │      │                  ├ [110]: https://linux.oracle.com/cve/CVE-2026-32283.html 
                        │      │                  ├ [111]: https://linux.oracle.com/errata/ELSA-2026-33722.html 
                        │      │                  ├ [112]: https://nvd.nist.gov/vuln/detail/CVE-2026-32283 
                        │      │                  ├ [113]: https://pkg.go.dev/vuln/GO-2026-4870 
                        │      │                  ├ [114]: https://security.access.redhat.com/data/csaf/v2/vex/
                        │      │                  │        2026/cve-2026-32283.json 
                        │      │                  ╰ [115]: https://www.cve.org/CVERecord?id=CVE-2026-32283 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.58Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:03.63Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2026-33811 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4981 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:271634e31a90bb17e78287691260e6fd1494c80cd1f10eb035834
                        │      │                   1cc514cec73 
                        │      ├ Title           : net: golang: Go net package: Denial of Service via long
                        │      │                   CNAME response in LookupCNAME 
                        │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME response can trigger a double-free of C memory
                        │      │                   and a crash. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-415 
                        │      │                  ╰ [1]: CWE-1341 
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
                        │      │                  ├ [7] : https://access.redhat.com/errata/RHSA-2026:34357 
                        │      │                  ├ [8] : https://access.redhat.com/errata/RHSA-2026:34359 
                        │      │                  ├ [9] : https://access.redhat.com/errata/RHSA-2026:34364 
                        │      │                  ├ [10]: https://access.redhat.com/security/cve/CVE-2026-33811 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2467822 
                        │      │                  ├ [12]: https://go.dev/cl/767860 
                        │      │                  ├ [13]: https://go.dev/issue/78803 
                        │      │                  ├ [14]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [15]: https://linux.oracle.com/cve/CVE-2026-33811.html 
                        │      │                  ├ [16]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ├ [18]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      │                  ├ [19]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33811.json 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:05.997Z 
                        ├ [16] ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7b6747f944f091bf3d989848841440ba96e05df87bdcd3142963e
                        │      │                   1ecf228563a 
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
                        │      │                  ├ [7] : https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2467815 
                        │      │                  ├ [9] : https://github.com/golang/go/issues/78476 
                        │      │                  ├ [10]: https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [11]: https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [12]: https://go.dev/cl/761581 
                        │      │                  ├ [13]: https://go.dev/cl/761640 
                        │      │                  ├ [14]: https://go.dev/issue/78476 
                        │      │                  ├ [15]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [16]: https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [17]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [18]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [19]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [20]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-33814.json 
                        │      │                  ├ [21]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [22]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [23]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [24]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [25]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:06.34Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2026-39820 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4986 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d1f6c5616e2251f0640542d9b093b9f0c9b900045ef1f79333515
                        │      │                   5b808d79477 
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
                        │      │                  ├ [6] : https://access.redhat.com/security/cve/CVE-2026-39820 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2467820 
                        │      │                  ├ [8] : https://go.dev/cl/759940 
                        │      │                  ├ [9] : https://go.dev/issue/78566 
                        │      │                  ├ [10]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2026-39820.html 
                        │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [13]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ├ [14]: https://pkg.go.dev/vuln/GO-2026-4986 
                        │      │                  ├ [15]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-39820.json 
                        │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-39820 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:11.933Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f1d0bd5a9c01154badad2f2a25e3af7b3178a0e0e0de1f6af51b6
                        │      │                   1ea3b9e0e46 
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
                        ├ [19] ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:b997832d66bef6457c7340bf7a368c93b42e7443f6ff13afe8e8e
                        │      │                   168c8a89efb 
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
                        │      │                  ├ [6] : https://access.redhat.com/security/cve/CVE-2026-42499 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/show_bug.cgi?id=2467809 
                        │      │                  ├ [8] : https://go.dev/cl/771520 
                        │      │                  ├ [9] : https://go.dev/issue/78987 
                        │      │                  ├ [10]: https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2026-42499.html 
                        │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [13]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ├ [14]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      │                  ├ [15]: https://security.access.redhat.com/data/csaf/v2/vex/2
                        │      │                  │       026/cve-2026-42499.json 
                        │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-42499 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-07-02T12:17:17.153Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:714f37ecff27d64d45d8e819e1da4713bb77d9f17096a0e6a0739
                        │      │                   cce54c80ef8 
                        │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid enc ... 
                        │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid encoded-words can consume excessive CPU. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-407 
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ├ azure  : 3 
                        │      │                  ╰ bitnami: 3 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/774481 
                        │      │                  ├ [1]: https://go.dev/issue/79217 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
                        │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
                        ├ [21] ╭ VulnerabilityID : CVE-2026-27142 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4603 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.8, 1.26.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27142 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:fe3009241b345425c63381cd3e74735a6cf70dad82c1eb46f1ecc
                        │      │                   1d645adcb97 
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
                        ├ [22] ╭ VulnerabilityID : CVE-2026-32282 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4864 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32282 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:45241ffcb777fe62e511324ee032b4eea274da049d7b653bf3433
                        │      │                   51eb9c0f08d 
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
                        │      │                  ├ [32]: https://linux.oracle.com/errata/ELSA-2026-19352.html 
                        │      │                  ├ [33]: https://nvd.nist.gov/vuln/detail/CVE-2026-32282 
                        │      │                  ├ [34]: https://pkg.go.dev/vuln/GO-2026-4864 
                        │      │                  ╰ [35]: https://www.cve.org/CVERecord?id=CVE-2026-32282 
                        │      ├ PublishedDate   : 2026-04-08T02:16:03.467Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:35:29.12Z 
                        ├ [23] ╭ VulnerabilityID : CVE-2026-32288 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4869 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32288 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2ca93fe067dc9329128109ff7ac4f92645f3f9a394e3e4aeb4101
                        │      │                   986803ba949 
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
                        ├ [24] ╭ VulnerabilityID : CVE-2026-32289 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4865 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.9, 1.26.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-32289 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:89d3c47514cd0372d2a9c5b9019b1f055c520817a598d75e99212
                        │      │                   b991f68e4a2 
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
                        ├ [25] ╭ VulnerabilityID : CVE-2026-39823 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4982 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:808dfeacaa43cf67ce1d6f59e6a8ef370e92f2b941aee1db88e29
                        │      │                   a75ece86566 
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
                        ├ [26] ╭ VulnerabilityID : CVE-2026-39825 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4976 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:a27a042115198ff845edab27481fff9a34a9ac4dcaa47313fd605
                        │      │                   75e10aca017 
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
                        ├ [27] ╭ VulnerabilityID : CVE-2026-39826 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4980 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f7dc840348cb54495fb41bf9dae52d29400cc4f0dc505feca66f4
                        │      │                   d25db260c8e 
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
                        ├ [28] ╭ VulnerabilityID : CVE-2026-42507 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5039 
                        │      ├ PkgID           : stdlib@v1.25.7 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                        │      │                  ╰ UID : 75587475cbb2f2ed 
                        │      ├ InstalledVersion: v1.25.7 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                        │      │                  │         52a20dd0e2b3b62af5b6 
                        │      │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                        │      │                            b279df2dec37df06a5a9 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:fc80aa71ab0a6c1c65fbfcf42712813580af54ffa99b5e6f3d82c
                        │      │                   4ce6e27f802 
                        │      ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                        │      │                   error messages via input injection 
                        │      ├ Description     : When returning errors, functions in the net/textproto
                        │      │                   package would include its input as part of the error. This
                        │      │                   might allow an attacker to inject misleading content to
                        │      │                   errors that are printed or logged. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ amazon     : 3 
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
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2026:29981 
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
                        ╰ [29] ╭ VulnerabilityID : CVE-2026-27139 
                               ├ VendorIDs        ─ [0]: GO-2026-4602 
                               ├ PkgID           : stdlib@v1.25.7 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.25.7 
                               │                  ╰ UID : 75587475cbb2f2ed 
                               ├ InstalledVersion: v1.25.7 
                               ├ FixedVersion    : 1.25.8, 1.26.1 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:4a5d63c538bdfc140f8349d90d824203f6dece95064e
                               │                  │         52a20dd0e2b3b62af5b6 
                               │                  ╰ DiffID: sha256:879c8470c49170a948b87f1a358b7b7b23770cb32f0c
                               │                            b279df2dec37df06a5a9 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27139 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:8e26c3c9bec0d80c62382ca232a93f5567c0cce0baca8981ee215
                               │                   28f244dffbb 
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

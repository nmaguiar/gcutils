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
│                       │     │                  ╰ UID : af9e86e80fd64186 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.18.8, 3.1.4, 2.21.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                       │     │                  │         4f5b0d61ceae5db4760 
│                       │     │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                       │     │                            038e3c23fcc218cc811 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54512 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:bece5510cedd59587d7a58eba9094304dc1ee0b63f42a8d475f3ba
│                       │     │                   9fad821b4f 
│                       │     ├ Title           : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionali ... 
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
│                       │     ├ VendorSeverity   ─ ghsa: 3 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H 
│                       │     │                         ╰ V3Score : 8.1 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/43
│                       │     │                  │      4d6c511de7fdd9872f29157aafb6162d12d8d5 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/issues/5988 
│                       │     │                  ╰ [3]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                         advisories/GHSA-j3rv-43j4-c7qm 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.203Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T21:01:36.47Z 
│                       ├ [1] ╭ VulnerabilityID : CVE-2026-54513 
│                       │     ├ VendorIDs        ─ [0]: GHSA-rmj7-2vxq-3g9f 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : af9e86e80fd64186 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.18.8, 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                       │     │                  │         4f5b0d61ceae5db4760 
│                       │     │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                       │     │                            038e3c23fcc218cc811 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54513 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:920ef5ddbed65d7cd82b750a03136e0b90c8d74368a8521c8b10d5
│                       │     │                   5544913a37 
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
│                       │     ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-54513 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/01
│                       │     │                  │      d1692c8d0ed03e51a0e3c4f8a9e6908e4931e5 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/commit/24
│                       │     │                  │      529da29fdf46ff94ca38de9ebf31cd188f5e8e 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/issues/5981 
│                       │     │                  ├ [5]: https://github.com/FasterXML/jackson-databind/issues/5983 
│                       │     │                  ├ [6]: https://github.com/FasterXML/jackson-databind/pull/5984 
│                       │     │                  ├ [7]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                  │      advisories/GHSA-rmj7-2vxq-3g9f 
│                       │     │                  ├ [8]: https://nvd.nist.gov/vuln/detail/CVE-2026-54513 
│                       │     │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-54513 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.333Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T21:00:19.3Z 
│                       ├ [2] ╭ VulnerabilityID : CVE-2026-54514 
│                       │     ├ VendorIDs        ─ [0]: GHSA-hgj6-7826-r7m5 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : af9e86e80fd64186 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.18.8, 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                       │     │                  │         4f5b0d61ceae5db4760 
│                       │     │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                       │     │                            038e3c23fcc218cc811 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54514 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:722d6685e0359756f36427f84d380a27d79eb344e55307f4cd1836
│                       │     │                   9724efeb7b 
│                       │     ├ Title           : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionali ... 
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
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N 
│                       │     │                         ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/1f
│                       │     │                  │      5a1037b1e9e05920e755cb35f198bcd46667e4 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/pull/5951 
│                       │     │                  ╰ [3]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                         advisories/GHSA-hgj6-7826-r7m5 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.467Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T20:55:09.61Z 
│                       ├ [3] ╭ VulnerabilityID : CVE-2026-54515 
│                       │     ├ VendorIDs        ─ [0]: GHSA-5jmj-h7xm-6q6v 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : af9e86e80fd64186 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 3.1.4, 2.18.9, 2.21.5 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                       │     │                  │         4f5b0d61ceae5db4760 
│                       │     │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                       │     │                            038e3c23fcc218cc811 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54515 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:2e67467ea2557e2ae1897080defba56d61e6c7241231d9dd4ddaa6
│                       │     │                   ee6532c10e 
│                       │     ├ Title           : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionali ... 
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
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N 
│                       │     │                         ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/0e
│                       │     │                  │      1b0b211f7a53baa62ba2f4c9bd006c7bf4d5fa 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/issues/5962 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/issues/5964 
│                       │     │                  ╰ [4]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                         advisories/GHSA-5jmj-h7xm-6q6v 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.597Z 
│                       │     ╰ LastModifiedDate: 2026-06-25T16:14:14.483Z 
│                       ├ [4] ╭ VulnerabilityID : CVE-2026-54516 
│                       │     ├ VendorIDs        ─ [0]: GHSA-9fxm-vc8v-hj55 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : af9e86e80fd64186 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                       │     │                  │         4f5b0d61ceae5db4760 
│                       │     │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                       │     │                            038e3c23fcc218cc811 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54516 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:800c75978e0133c7d2d41d02192e760e0c9f9f8d065ece1006aa9c
│                       │     │                   2a2d1a31b1 
│                       │     ├ Title           : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionali ... 
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
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N 
│                       │     │                         ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/c3
│                       │     │                  │      d56dd25d52319828147c5b9aeabf2d485c250a 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/e8
│                       │     │                  │      8cb17006b6af4883b973058f0bb6486e5074af 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/pull/5967 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/pull/5968 
│                       │     │                  ╰ [5]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                         advisories/GHSA-9fxm-vc8v-hj55 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.723Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T20:52:12.103Z 
│                       ├ [5] ╭ VulnerabilityID : CVE-2026-54517 
│                       │     ├ VendorIDs        ─ [0]: GHSA-5hh8-q8hv-fr38 
│                       │     ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                       │     ├ PkgPath         : openaf/openaf.jar 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                       │     │                  │       2.21.3 
│                       │     │                  ╰ UID : af9e86e80fd64186 
│                       │     ├ InstalledVersion: 2.21.3 
│                       │     ├ FixedVersion    : 2.21.4, 3.1.4 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                       │     │                  │         4f5b0d61ceae5db4760 
│                       │     │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                       │     │                            038e3c23fcc218cc811 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54517 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:7e157f0c67c578300368ae69aa6b672881d2b76c92737a1763e915
│                       │     │                   5867e7cd58 
│                       │     ├ Title           : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionali ... 
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
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N 
│                       │     │                         ╰ V3Score : 5.3 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/5b
│                       │     │                  │      f23edb4221f7dd2ec8e71ff6d26c61640f261d 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/94
│                       │     │                  │      c5d215b3af1505098c686405d9641f041a9962 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/pull/5969 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/pull/5970 
│                       │     │                  ╰ [5]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                         advisories/GHSA-5hh8-q8hv-fr38 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.853Z 
│                       │     ╰ LastModifiedDate: 2026-06-27T20:51:09.987Z 
│                       ╰ [6] ╭ VulnerabilityID : CVE-2026-54518 
│                             ├ VendorIDs        ─ [0]: GHSA-rcqc-6cw3-h962 
│                             ├ PkgName         : com.fasterxml.jackson.core:jackson-databind 
│                             ├ PkgPath         : openaf/openaf.jar 
│                             ├ PkgIdentifier    ╭ PURL: pkg:maven/com.fasterxml.jackson.core/jackson-databind@
│                             │                  │       2.21.3 
│                             │                  ╰ UID : af9e86e80fd64186 
│                             ├ InstalledVersion: 2.21.3 
│                             ├ FixedVersion    : 2.21.4 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd7
│                             │                  │         4f5b0d61ceae5db4760 
│                             │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d3
│                             │                            038e3c23fcc218cc811 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54518 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:d976b2872274fe4ba54da3e8265fcb1651df004f55ca1f0df193b4
│                             │                   5a93714d27 
│                             ├ Title           : jackson-databind contains the general-purpose data-binding
│                             │                   functionali ... 
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
│                             ├ VendorSeverity   ─ ghsa: 2 
│                             ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N 
│                             │                         ╰ V3Score : 6.5 
│                             ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                             │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/72
│                             │                  │      1fa07ebbd4aab4a659a1a68940878315c3e341 
│                             │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/d6
│                             │                  │      33bc038f200c1397c07f1a2b46f58e72c91eea 
│                             │                  ├ [3]: https://github.com/FasterXML/jackson-databind/pull/5971 
│                             │                  ├ [4]: https://github.com/FasterXML/jackson-databind/pull/5973 
│                             │                  ╰ [5]: https://github.com/FasterXML/jackson-databind/security/
│                             │                         advisories/GHSA-rcqc-6cw3-h962 
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
├ [4] ╭ Target         : usr/bin/prometheus 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-39827 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5016 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39827 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:644dc6b402ceaa1496649a8de8c36ab910cf2069a29f3429de10b
│                       │      │                   23c162ba558 
│                       │      ├ Title           : An authenticated SSH client that repeatedly opened channels
│                       │      │                   which were ... 
│                       │      ├ Description     : An authenticated SSH client that repeatedly opened channels
│                       │      │                   which were rejected by the server caused unbounded memory
│                       │      │                   growth, eventually crashing the server process and affecting
│                       │      │                    all connected users. Rejected channels are now properly
│                       │      │                   removed from the connection's internal state and released
│                       │      │                   for garbage collection. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-924 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ azure : 2 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/781320 
│                       │      │                  ├ [1]: https://go.dev/issue/35127 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39827 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5016 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:21.497Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.063Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-39828 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5014 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39828 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:d39f4a1e942c003701e74472a57fcefea6f8c38e51e13b7dff75b
│                       │      │                   57c33d7a373 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh:
│                       │      │                   Unauthorized command execution via discarded SSH
│                       │      │                   permissions 
│                       │      ├ Description     : When an SSH server authentication callback returned
│                       │      │                   PartialSuccessError with non-nil Permissions, those
│                       │      │                   permissions were silently discarded, potentially dropping
│                       │      │                   certificate restrictions such as force-command after a
│                       │      │                   second factor succeeded. Returning non-nil Permissions with
│                       │      │                   PartialSuccessError now results in a connection error. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-295 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 8.8 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39828 
│                       │      │                  ├ [1]: https://go.dev/cl/781621 
│                       │      │                  ├ [2]: https://go.dev/issue/79562 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39828 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5014 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-39828 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.19Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.207Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-39829 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5018 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39829 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:65be55aef8bdd674654e8f228c481c9bcd238b811430982b87806
│                       │      │                   614a531c9a8 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
│                       │      │                   Service via crafted public key with excessive parameters 
│                       │      ├ Description     : The RSA and DSA public key parsers did not enforce size
│                       │      │                   limits on key parameters. A crafted public key with an
│                       │      │                   excessively large modulus or DSA parameter could cause
│                       │      │                   several minutes of CPU consumption during signature
│                       │      │                   verification. This could be triggered by unauthenticated
│                       │      │                   clients during public key authentication. RSA moduli are now
│                       │      │                    limited to 8192 bits, and DSA parameters are validated per
│                       │      │                   FIPS 186-2. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-347 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 3 
│                       │      │                  ├ azure      : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ╰ rocky      : 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29455 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39829 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2480681 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2480684 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
│                       │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
│                       │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
│                       │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
│                       │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-25679 
│                       │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32280 
│                       │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32281 
│                       │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32283 
│                       │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39829 
│                       │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39830 
│                       │      │                  ├ [20]: https://errata.almalinux.org/9/ALSA-2026-29455.html 
│                       │      │                  ├ [21]: https://errata.rockylinux.org/RLSA-2026:29455 
│                       │      │                  ├ [22]: https://go.dev/cl/781641 
│                       │      │                  ├ [23]: https://go.dev/cl/781661 
│                       │      │                  ├ [24]: https://go.dev/issue/79565 
│                       │      │                  ├ [25]: https://groups.google.com/g/golang-announce/c/a082jnz
│                       │      │                  │       -LvI 
│                       │      │                  ├ [26]: https://linux.oracle.com/cve/CVE-2026-39829.html 
│                       │      │                  ├ [27]: https://linux.oracle.com/errata/ELSA-2026-29455.html 
│                       │      │                  ├ [28]: https://nvd.nist.gov/vuln/detail/CVE-2026-39829 
│                       │      │                  ├ [29]: https://pkg.go.dev/vuln/GO-2026-5018 
│                       │      │                  ╰ [30]: https://www.cve.org/CVERecord?id=CVE-2026-39829 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.31Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.343Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-39830 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5017 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39830 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f7d1a5fe1a97d1468aeadfd176cb7325d9099dd1c45145fa53be0
│                       │      │                   92c7faa9c0d 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
│                       │      │                   Service via resource leak from unsolicited SSH responses 
│                       │      ├ Description     : A malicious SSH peer could send unsolicited global request
│                       │      │                   responses to fill an internal buffer, blocking the
│                       │      │                   connection's read loop. The blocked goroutine could not be
│                       │      │                   released by calling Close(), resulting in a resource leak
│                       │      │                   per connection. Unsolicited global responses are now
│                       │      │                   discarded. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-119 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 3 
│                       │      │                  ├ azure      : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ├ rocky      : 3 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29455 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39830 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2480681 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2480684 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
│                       │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
│                       │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
│                       │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
│                       │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-25679 
│                       │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32280 
│                       │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32281 
│                       │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32283 
│                       │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39829 
│                       │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39830 
│                       │      │                  ├ [20]: https://errata.almalinux.org/9/ALSA-2026-29455.html 
│                       │      │                  ├ [21]: https://errata.rockylinux.org/RLSA-2026:29455 
│                       │      │                  ├ [22]: https://github.com/golang/crypto/commit/4e7a7384ecbc8
│                       │      │                  │       d519f6f4c11b36fa9d761fc8946 
│                       │      │                  ├ [23]: https://go.dev/cl/781640 
│                       │      │                  ├ [24]: https://go.dev/cl/781664 
│                       │      │                  ├ [25]: https://go.dev/issue/79564 
│                       │      │                  ├ [26]: https://groups.google.com/g/golang-announce/c/a082jnz
│                       │      │                  │       -LvI 
│                       │      │                  ├ [27]: https://linux.oracle.com/cve/CVE-2026-39830.html 
│                       │      │                  ├ [28]: https://linux.oracle.com/errata/ELSA-2026-29455.html 
│                       │      │                  ├ [29]: https://nvd.nist.gov/vuln/detail/CVE-2026-39830 
│                       │      │                  ├ [30]: https://pkg.go.dev/vuln/GO-2026-5017 
│                       │      │                  ├ [31]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [32]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ├ [33]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-39830 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.483Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39832 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5006 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39832 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f95dfbf3a0f04c70131630e0b34e34eaccb740c284a5ccb205173
│                       │      │                   23de5bd667f 
│                       │      ├ Title           : golang.org/x/crypto/ssh/agent:
│                       │      │                   golang.org/x/crypto/ssh/agent: Security bypass due to
│                       │      │                   improper handling of key restrictions 
│                       │      ├ Description     : When adding a key to a remote agent constraint extensions
│                       │      │                   such as restrict-destination-v00@openssh.com were not
│                       │      │                   serialized in the request. Destination restrictions were
│                       │      │                   silently stripped when forwarding keys, allowing
│                       │      │                   unrestricted use of the key on the remote host. The client
│                       │      │                   now serializes all constraint extensions. Additionally, the
│                       │      │                   in-memory keyring returned by NewKeyring() now rejects keys
│                       │      │                   with unsupported constraint extensions instead of silently
│                       │      │                   ignoring them. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-502 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 8.7 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39832 
│                       │      │                  ├ [1]: https://github.com/golang/crypto/commit/e3d1254f1e7e60
│                       │      │                  │      baa086142c46174bf6d8d0fe50 
│                       │      │                  ├ [2]: https://go.dev/cl/778642 
│                       │      │                  ├ [3]: https://go.dev/issue/79435 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39832 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5006 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39832 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.663Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.773Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-39835 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5015 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39835 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:0350cd46e266210aa24740fb54d47323498622f3e8bbeb97ef34d
│                       │      │                   1d5dccdc81e 
│                       │      ├ Title           : SSH servers which use CertChecker as a public key callback
│                       │      │                   without set ... 
│                       │      ├ Description     : SSH servers which use CertChecker as a public key callback
│                       │      │                   without setting IsUserAuthority or IsHostAuthority could be
│                       │      │                   caused to panic by a client presenting a certificate.
│                       │      │                   CertChecker now returns an error instead of panicking when
│                       │      │                   these callbacks are nil. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-295 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ azure : 2 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/781660 
│                       │      │                  ├ [1]: https://go.dev/issue/79563 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39835 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5015 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:24.53Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:40.197Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-42508 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5021 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42508 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4d6c5a8f3c1a732bfc73a8a9d6f9baaabcf7514cae8cec0931d87
│                       │      │                   039b5e84fc1 
│                       │      ├ Title           : golang.org/x/crypto/ssh/knownhosts: golang:
│                       │      │                   golang.org/x/crypto/ssh/knownhosts: Revocation bypass via
│                       │      │                   unchecked SignatureKey 
│                       │      ├ Description     : Previously, a revoked 'SignatureKey' belonging to a CA was
│                       │      │                   not correctly checked for revocation. Now, both the 'key'
│                       │      │                   and 'key.SignatureKey' are checked for @revoked. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-295 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 7.4 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42508 
│                       │      │                  ├ [1]: https://github.com/golang/crypto/commit/f717e29698a271
│                       │      │                  │      c548239ed56bf5dd9516d6f7e8 
│                       │      │                  ├ [2]: https://go.dev/cl/781220 
│                       │      │                  ├ [3]: https://go.dev/issue/79568 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-42508 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5021 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42508 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:25.44Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:47:57.267Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-46595 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5023 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46595 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:de40c57b4ad90811b5763209632a26d2f3b5fd0d2e9a11f184a25
│                       │      │                   56310c7bb87 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh:
│                       │      │                   Authorization bypass due to skipped source-address
│                       │      │                   validation 
│                       │      ├ Description     : Previously, CVE-2024-45337 fixed an authorization bypass for
│                       │      │                    misused ssh server configurations; if any other type of
│                       │      │                   callback is passed other than public key, then the
│                       │      │                   source-address validation would be skipped. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-863 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 7.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46595 
│                       │      │                  ├ [1]: https://github.com/golang/crypto/commit/533fb3f7e4a5ae
│                       │      │                  │      23f69d1837cd851d35ff5b76ce 
│                       │      │                  ├ [2]: https://go.dev/cl/781642 
│                       │      │                  ├ [3]: https://go.dev/issue/79570 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-46595 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5023 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-46595 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:25.55Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:53:47.24Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-46597 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5013 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46597 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:fe46c0e898038e81160e79287fed9f45ad9bc04820917cccd46d8
│                       │      │                   c0d00688af5 
│                       │      ├ Title           : An incorrectly placed cast from bytes to int allowed for
│                       │      │                   server-side p ... 
│                       │      ├ Description     : An incorrectly placed cast from bytes to int allowed for
│                       │      │                   server-side panic in the AES-GCM packet decoder for
│                       │      │                   well-crafted inputs. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-704 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ azure : 3 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/781620 
│                       │      │                  ├ [1]: https://go.dev/issue/79561 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-46597 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5013 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:26.003Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:53:47.38Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-39831 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5019 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39831 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:ae630244add86412e80afdfbd29ef84f8dbb97a1824e46304be5d
│                       │      │                   83bceb2f40e 
│                       │      ├ Title           : The Verify() method for FIDO/U2F security key types
│                       │      │                   (sk-ecdsa-sha2-nis ... 
│                       │      ├ Description     : The Verify() method for FIDO/U2F security key types
│                       │      │                   (sk-ecdsa-sha2-nistp256@openssh.com,
│                       │      │                   sk-ssh-ed25519@openssh.com) did not check the User Presence
│                       │      │                   flag. Signatures generated without physical touch were
│                       │      │                   accepted, allowing unattended use of a hardware security
│                       │      │                   key. To restore the previous behavior, return a
│                       │      │                   "no-touch-required" extension in Permissions.Extensions from
│                       │      │                    PublicKeyCallback. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-862 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/b61cf853a89d82
│                       │      │                  │      cad68da5e12a6beca2116f8456 
│                       │      │                  ├ [1]: https://go.dev/cl/781662 
│                       │      │                  ├ [2]: https://go.dev/issue/79566 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://pkg.go.dev/vuln/GO-2026-5019 
│                       │      │                  ├ [5]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39831 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.553Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.63Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-39833 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5005 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39833 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:c8ce4d62a1e785d6cab9c7128d064c99226127fab4f3b899c8356
│                       │      │                   2b702042b04 
│                       │      ├ Title           : The in-memory keyring returned by NewKeyring() silently
│                       │      │                   accepted keys  ... 
│                       │      ├ Description     : The in-memory keyring returned by NewKeyring() silently
│                       │      │                   accepted keys with the ConfirmBeforeUse constraint but never
│                       │      │                    enforced it. The key would sign without any confirmation
│                       │      │                   prompt, with no indication to the caller that the constraint
│                       │      │                    was not in effect. NewKeyring() now returns an error when
│                       │      │                   unsupported constraints are requested. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-862 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/0fb843a4722256
│                       │      │                  │      45e917c84f1f9744757f0bab14 
│                       │      │                  ├ [1]: https://go.dev/cl/778640 
│                       │      │                  ├ [2]: https://go.dev/cl/778641 
│                       │      │                  ├ [3]: https://go.dev/issue/79436 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39833 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5005 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39833 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.773Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.913Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-39834 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5020 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39834 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:8a85d5d6e9a92a8b0669841afd5300378274ba92251fe5cef6821
│                       │      │                   04d04996614 
│                       │      ├ Title           : When writing data larger than 4GB in a single Write call on
│                       │      │                   an SSH cha ... 
│                       │      ├ Description     : When writing data larger than 4GB in a single Write call on
│                       │      │                   an SSH channel, an integer overflow in the internal payload
│                       │      │                   size calculation caused the write loop to spin indefinitely,
│                       │      │                    sending empty packets without making progress. The size
│                       │      │                   comparison now uses int64 to prevent truncation. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-190 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/e052873987615d
│                       │      │                  │      c96fe67607a9a6adb76311344f 
│                       │      │                  ├ [1]: https://go.dev/cl/781663 
│                       │      │                  ├ [2]: https://go.dev/issue/79567 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39834 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5020 
│                       │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39834 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:24.237Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:40.057Z 
│                       ├ [12] ╭ VulnerabilityID : CVE-2026-46598 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5033 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46598 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:97111f6628ca9b6f420bacfb954dfec0ddad3b61d761d2920fb1a
│                       │      │                   2909f638625 
│                       │      ├ Title           : golang.org/x/crypto/ssh/agent: golang:
│                       │      │                   golang.org/x/crypto/ssh/agent: Denial of Service via
│                       │      │                   malformed input 
│                       │      ├ Description     : For certain crafted inputs, a 'ed25519.PrivateKey' was
│                       │      │                   created by casting malformed wire bytes, leading to a panic
│                       │      │                   when used. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-129 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46598 
│                       │      │                  ├ [1]: https://go.dev/cl/781360 
│                       │      │                  ├ [2]: https://go.dev/issue/79596 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46598 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5033 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46598 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:26.537Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:53:47.52Z 
│                       ├ [13] ╭ VulnerabilityID : CVE-2026-27145 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : 66f3023025d60df9 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:2604244d3398299128cede73680873e6ceb0b6cfa174de6f8de07
│                       │      │                   baaba086ca6 
│                       │      ├ Title           : *x509.Certificate).VerifyHostname previously called
│                       │      │                   matchHostnames in ... 
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
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:H 
│                       │      │                            ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │      │                  ├ [1]: https://go.dev/issue/79694 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:26:45.23Z 
│                       ├ [14] ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : 66f3023025d60df9 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:dc4218b513c514fd1098d7088274b662ee8d4adb48553512b300f
│                       │      │                   49469cad7c5 
│                       │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid enc ... 
│                       │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid encoded-words can consume excessive CPU. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 3 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │      │                  ├ [1]: https://go.dev/issue/79217 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
│                       ╰ [15] ╭ VulnerabilityID : CVE-2026-42507 
│                              ├ VendorIDs        ─ [0]: GO-2026-5039 
│                              ├ PkgID           : stdlib@v1.26.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                              │                  ╰ UID : 66f3023025d60df9 
│                              ├ InstalledVersion: v1.26.3 
│                              ├ FixedVersion    : 1.25.11, 1.26.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                              │                  │         74f5b0d61ceae5db4760 
│                              │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                              │                            3038e3c23fcc218cc811 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:2b1f40ed3d52a733c9ee2ae2fe070e36a862ad0ad933a7a317111
│                              │                   6861718e5b4 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ amazon     : 3 
│                              │                  ├ bitnami    : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
│                              │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-42507 
│                              │                  ├ [3] : https://errata.rockylinux.org/RLSA-2026:29981 
│                              │                  ├ [4] : https://go.dev/cl/777060 
│                              │                  ├ [5] : https://go.dev/issue/79346 
│                              │                  ├ [6] : https://groups.google.com/g/golang-announce/c/tKs3rmc
│                              │                  │       BcKw 
│                              │                  ├ [7] : https://linux.oracle.com/cve/CVE-2026-42507.html 
│                              │                  ├ [8] : https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                              │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [10]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                              ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                              ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-39827 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5016 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39827 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:0c210e8b3ae07fa9461937d4abd90f46e389545433e8ef8a8a0f4
│                       │      │                   5c4b4908296 
│                       │      ├ Title           : An authenticated SSH client that repeatedly opened channels
│                       │      │                   which were ... 
│                       │      ├ Description     : An authenticated SSH client that repeatedly opened channels
│                       │      │                   which were rejected by the server caused unbounded memory
│                       │      │                   growth, eventually crashing the server process and affecting
│                       │      │                    all connected users. Rejected channels are now properly
│                       │      │                   removed from the connection's internal state and released
│                       │      │                   for garbage collection. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-924 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ azure : 2 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/781320 
│                       │      │                  ├ [1]: https://go.dev/issue/35127 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39827 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5016 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:21.497Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.063Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-39828 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5014 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39828 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:caa2ae6b118744091436d74d7d68c3a424a0f6d58e35e0bcea94f
│                       │      │                   815db7f9121 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh:
│                       │      │                   Unauthorized command execution via discarded SSH
│                       │      │                   permissions 
│                       │      ├ Description     : When an SSH server authentication callback returned
│                       │      │                   PartialSuccessError with non-nil Permissions, those
│                       │      │                   permissions were silently discarded, potentially dropping
│                       │      │                   certificate restrictions such as force-command after a
│                       │      │                   second factor succeeded. Returning non-nil Permissions with
│                       │      │                   PartialSuccessError now results in a connection error. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-295 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 8.8 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39828 
│                       │      │                  ├ [1]: https://go.dev/cl/781621 
│                       │      │                  ├ [2]: https://go.dev/issue/79562 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39828 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5014 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-39828 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.19Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.207Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-39829 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5018 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39829 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b4088359e6cf1a2a431d23333667e9a0b53fa0fa5a2974d3f6a1d
│                       │      │                   13d81a7edf1 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
│                       │      │                   Service via crafted public key with excessive parameters 
│                       │      ├ Description     : The RSA and DSA public key parsers did not enforce size
│                       │      │                   limits on key parameters. A crafted public key with an
│                       │      │                   excessively large modulus or DSA parameter could cause
│                       │      │                   several minutes of CPU consumption during signature
│                       │      │                   verification. This could be triggered by unauthenticated
│                       │      │                   clients during public key authentication. RSA moduli are now
│                       │      │                    limited to 8192 bits, and DSA parameters are validated per
│                       │      │                   FIPS 186-2. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-347 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 3 
│                       │      │                  ├ azure      : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ╰ rocky      : 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29455 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39829 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2480681 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2480684 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
│                       │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
│                       │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
│                       │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
│                       │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-25679 
│                       │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32280 
│                       │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32281 
│                       │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32283 
│                       │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39829 
│                       │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39830 
│                       │      │                  ├ [20]: https://errata.almalinux.org/9/ALSA-2026-29455.html 
│                       │      │                  ├ [21]: https://errata.rockylinux.org/RLSA-2026:29455 
│                       │      │                  ├ [22]: https://go.dev/cl/781641 
│                       │      │                  ├ [23]: https://go.dev/cl/781661 
│                       │      │                  ├ [24]: https://go.dev/issue/79565 
│                       │      │                  ├ [25]: https://groups.google.com/g/golang-announce/c/a082jnz
│                       │      │                  │       -LvI 
│                       │      │                  ├ [26]: https://linux.oracle.com/cve/CVE-2026-39829.html 
│                       │      │                  ├ [27]: https://linux.oracle.com/errata/ELSA-2026-29455.html 
│                       │      │                  ├ [28]: https://nvd.nist.gov/vuln/detail/CVE-2026-39829 
│                       │      │                  ├ [29]: https://pkg.go.dev/vuln/GO-2026-5018 
│                       │      │                  ╰ [30]: https://www.cve.org/CVERecord?id=CVE-2026-39829 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.31Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.343Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-39830 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5017 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39830 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:a981e9bf6c160ae9f9d8454251856631b4308c396ca8699142602
│                       │      │                   aec8d7b1e6a 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
│                       │      │                   Service via resource leak from unsolicited SSH responses 
│                       │      ├ Description     : A malicious SSH peer could send unsolicited global request
│                       │      │                   responses to fill an internal buffer, blocking the
│                       │      │                   connection's read loop. The blocked goroutine could not be
│                       │      │                   released by calling Close(), resulting in a resource leak
│                       │      │                   per connection. Unsolicited global responses are now
│                       │      │                   discarded. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-119 
│                       │      ├ VendorSeverity   ╭ alma       : 3 
│                       │      │                  ├ amazon     : 3 
│                       │      │                  ├ azure      : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ├ rocky      : 3 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29455 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39830 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2480681 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2480684 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
│                       │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
│                       │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
│                       │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
│                       │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-25679 
│                       │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32280 
│                       │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32281 
│                       │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-32283 
│                       │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39829 
│                       │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       26-39830 
│                       │      │                  ├ [20]: https://errata.almalinux.org/9/ALSA-2026-29455.html 
│                       │      │                  ├ [21]: https://errata.rockylinux.org/RLSA-2026:29455 
│                       │      │                  ├ [22]: https://github.com/golang/crypto/commit/4e7a7384ecbc8
│                       │      │                  │       d519f6f4c11b36fa9d761fc8946 
│                       │      │                  ├ [23]: https://go.dev/cl/781640 
│                       │      │                  ├ [24]: https://go.dev/cl/781664 
│                       │      │                  ├ [25]: https://go.dev/issue/79564 
│                       │      │                  ├ [26]: https://groups.google.com/g/golang-announce/c/a082jnz
│                       │      │                  │       -LvI 
│                       │      │                  ├ [27]: https://linux.oracle.com/cve/CVE-2026-39830.html 
│                       │      │                  ├ [28]: https://linux.oracle.com/errata/ELSA-2026-29455.html 
│                       │      │                  ├ [29]: https://nvd.nist.gov/vuln/detail/CVE-2026-39830 
│                       │      │                  ├ [30]: https://pkg.go.dev/vuln/GO-2026-5017 
│                       │      │                  ├ [31]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [32]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ├ [33]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-39830 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.483Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39832 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5006 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39832 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5c783d1d9e472937624e479f79f7591f562f0d48068aac29df44c
│                       │      │                   8d0ab2c59e3 
│                       │      ├ Title           : golang.org/x/crypto/ssh/agent:
│                       │      │                   golang.org/x/crypto/ssh/agent: Security bypass due to
│                       │      │                   improper handling of key restrictions 
│                       │      ├ Description     : When adding a key to a remote agent constraint extensions
│                       │      │                   such as restrict-destination-v00@openssh.com were not
│                       │      │                   serialized in the request. Destination restrictions were
│                       │      │                   silently stripped when forwarding keys, allowing
│                       │      │                   unrestricted use of the key on the remote host. The client
│                       │      │                   now serializes all constraint extensions. Additionally, the
│                       │      │                   in-memory keyring returned by NewKeyring() now rejects keys
│                       │      │                   with unsupported constraint extensions instead of silently
│                       │      │                   ignoring them. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-502 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 8.7 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39832 
│                       │      │                  ├ [1]: https://github.com/golang/crypto/commit/e3d1254f1e7e60
│                       │      │                  │      baa086142c46174bf6d8d0fe50 
│                       │      │                  ├ [2]: https://go.dev/cl/778642 
│                       │      │                  ├ [3]: https://go.dev/issue/79435 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39832 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5006 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39832 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.663Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.773Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-39835 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5015 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39835 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:c013c18ff2c197304542ce7760d60a92ac00454455965e15c9e57
│                       │      │                   d1a3989a569 
│                       │      ├ Title           : SSH servers which use CertChecker as a public key callback
│                       │      │                   without set ... 
│                       │      ├ Description     : SSH servers which use CertChecker as a public key callback
│                       │      │                   without setting IsUserAuthority or IsHostAuthority could be
│                       │      │                   caused to panic by a client presenting a certificate.
│                       │      │                   CertChecker now returns an error instead of panicking when
│                       │      │                   these callbacks are nil. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-295 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ azure : 2 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/781660 
│                       │      │                  ├ [1]: https://go.dev/issue/79563 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39835 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5015 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:24.53Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:40.197Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-42508 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5021 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42508 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f35ec85608494c6b6a566103e632c5a1f80127300da11c368da99
│                       │      │                   c807242e68f 
│                       │      ├ Title           : golang.org/x/crypto/ssh/knownhosts: golang:
│                       │      │                   golang.org/x/crypto/ssh/knownhosts: Revocation bypass via
│                       │      │                   unchecked SignatureKey 
│                       │      ├ Description     : Previously, a revoked 'SignatureKey' belonging to a CA was
│                       │      │                   not correctly checked for revocation. Now, both the 'key'
│                       │      │                   and 'key.SignatureKey' are checked for @revoked. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-295 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 7.4 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42508 
│                       │      │                  ├ [1]: https://github.com/golang/crypto/commit/f717e29698a271
│                       │      │                  │      c548239ed56bf5dd9516d6f7e8 
│                       │      │                  ├ [2]: https://go.dev/cl/781220 
│                       │      │                  ├ [3]: https://go.dev/issue/79568 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-42508 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5021 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42508 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:25.44Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:47:57.267Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-46595 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5023 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46595 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:505500a9662d87a5c44e6cc58f0d4853b8d208e33e6b796d57386
│                       │      │                   5cb790d17c7 
│                       │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh:
│                       │      │                   Authorization bypass due to skipped source-address
│                       │      │                   validation 
│                       │      ├ Description     : Previously, CVE-2024-45337 fixed an authorization bypass for
│                       │      │                    misused ssh server configurations; if any other type of
│                       │      │                   callback is passed other than public key, then the
│                       │      │                   source-address validation would be skipped. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-863 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 7.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46595 
│                       │      │                  ├ [1]: https://github.com/golang/crypto/commit/533fb3f7e4a5ae
│                       │      │                  │      23f69d1837cd851d35ff5b76ce 
│                       │      │                  ├ [2]: https://go.dev/cl/781642 
│                       │      │                  ├ [3]: https://go.dev/issue/79570 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-46595 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5023 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-46595 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:25.55Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:53:47.24Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-46597 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5013 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46597 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f259ff498615cbe3ad5ee0bc2d6b91e9d4a1391887319c32f3a03
│                       │      │                   540017946d0 
│                       │      ├ Title           : An incorrectly placed cast from bytes to int allowed for
│                       │      │                   server-side p ... 
│                       │      ├ Description     : An incorrectly placed cast from bytes to int allowed for
│                       │      │                   server-side panic in the AES-GCM packet decoder for
│                       │      │                   well-crafted inputs. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-704 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ azure : 3 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/781620 
│                       │      │                  ├ [1]: https://go.dev/issue/79561 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-46597 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5013 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:26.003Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:53:47.38Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-39831 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5019 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39831 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:07f79c886ad3c6e488f5efd78d0f4f5e0b979ff43ec87321abc17
│                       │      │                   b85087e4f11 
│                       │      ├ Title           : The Verify() method for FIDO/U2F security key types
│                       │      │                   (sk-ecdsa-sha2-nis ... 
│                       │      ├ Description     : The Verify() method for FIDO/U2F security key types
│                       │      │                   (sk-ecdsa-sha2-nistp256@openssh.com,
│                       │      │                   sk-ssh-ed25519@openssh.com) did not check the User Presence
│                       │      │                   flag. Signatures generated without physical touch were
│                       │      │                   accepted, allowing unattended use of a hardware security
│                       │      │                   key. To restore the previous behavior, return a
│                       │      │                   "no-touch-required" extension in Permissions.Extensions from
│                       │      │                    PublicKeyCallback. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-862 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/b61cf853a89d82
│                       │      │                  │      cad68da5e12a6beca2116f8456 
│                       │      │                  ├ [1]: https://go.dev/cl/781662 
│                       │      │                  ├ [2]: https://go.dev/issue/79566 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://pkg.go.dev/vuln/GO-2026-5019 
│                       │      │                  ├ [5]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39831 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.553Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.63Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-39833 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5005 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39833 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f12862bc902242f5343032b57882c42005b9b03456fa479378458
│                       │      │                   cb0a49d2ab7 
│                       │      ├ Title           : The in-memory keyring returned by NewKeyring() silently
│                       │      │                   accepted keys  ... 
│                       │      ├ Description     : The in-memory keyring returned by NewKeyring() silently
│                       │      │                   accepted keys with the ConfirmBeforeUse constraint but never
│                       │      │                    enforced it. The key would sign without any confirmation
│                       │      │                   prompt, with no indication to the caller that the constraint
│                       │      │                    was not in effect. NewKeyring() now returns an error when
│                       │      │                   unsupported constraints are requested. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-862 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/0fb843a4722256
│                       │      │                  │      45e917c84f1f9744757f0bab14 
│                       │      │                  ├ [1]: https://go.dev/cl/778640 
│                       │      │                  ├ [2]: https://go.dev/cl/778641 
│                       │      │                  ├ [3]: https://go.dev/issue/79436 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39833 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5005 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39833 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.773Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.913Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2026-39834 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5020 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39834 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:f170e120fbaa0274e9331469cbedc425402b2079eb916449e18b3
│                       │      │                   fac7d3f4750 
│                       │      ├ Title           : When writing data larger than 4GB in a single Write call on
│                       │      │                   an SSH cha ... 
│                       │      ├ Description     : When writing data larger than 4GB in a single Write call on
│                       │      │                   an SSH channel, an integer overflow in the internal payload
│                       │      │                   size calculation caused the write loop to spin indefinitely,
│                       │      │                    sending empty packets without making progress. The size
│                       │      │                   comparison now uses int64 to prevent truncation. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-190 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/e052873987615d
│                       │      │                  │      c96fe67607a9a6adb76311344f 
│                       │      │                  ├ [1]: https://go.dev/cl/781663 
│                       │      │                  ├ [2]: https://go.dev/issue/79567 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39834 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5020 
│                       │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39834 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:24.237Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:40.057Z 
│                       ├ [12] ╭ VulnerabilityID : CVE-2026-46598 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5033 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46598 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4758013f21ac1f215bd147ea9b463944ca500d9cdb54e5e93e924
│                       │      │                   75c7241b874 
│                       │      ├ Title           : golang.org/x/crypto/ssh/agent: golang:
│                       │      │                   golang.org/x/crypto/ssh/agent: Denial of Service via
│                       │      │                   malformed input 
│                       │      ├ Description     : For certain crafted inputs, a 'ed25519.PrivateKey' was
│                       │      │                   created by casting malformed wire bytes, leading to a panic
│                       │      │                   when used. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-129 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 2 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46598 
│                       │      │                  ├ [1]: https://go.dev/cl/781360 
│                       │      │                  ├ [2]: https://go.dev/issue/79596 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46598 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5033 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46598 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:26.537Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:53:47.52Z 
│                       ├ [13] ╭ VulnerabilityID : CVE-2026-27145 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : df6aa20024d653e1 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:ac9c1966f3a20a9d574a402b3a4e4f4fc8b1160bb4cca5ff30e45
│                       │      │                   d938d9e208e 
│                       │      ├ Title           : *x509.Certificate).VerifyHostname previously called
│                       │      │                   matchHostnames in ... 
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
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:H 
│                       │      │                            ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │      │                  ├ [1]: https://go.dev/issue/79694 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:26:45.23Z 
│                       ├ [14] ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : df6aa20024d653e1 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:56d86a47cfe9c0813e0a13548d133de5037ecadaaca85c58b52ee
│                       │      │                   d3606db51e5 
│                       │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid enc ... 
│                       │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid encoded-words can consume excessive CPU. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 3 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │      │                  ├ [1]: https://go.dev/issue/79217 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
│                       ╰ [15] ╭ VulnerabilityID : CVE-2026-42507 
│                              ├ VendorIDs        ─ [0]: GO-2026-5039 
│                              ├ PkgID           : stdlib@v1.26.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                              │                  ╰ UID : df6aa20024d653e1 
│                              ├ InstalledVersion: v1.26.3 
│                              ├ FixedVersion    : 1.25.11, 1.26.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                              │                  │         74f5b0d61ceae5db4760 
│                              │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                              │                            3038e3c23fcc218cc811 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:a0e3e0bfd36c793065c130f3d4cee61485633c7d6cc654276fd23
│                              │                   65b4cf70dc7 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ amazon     : 3 
│                              │                  ├ bitnami    : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
│                              │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-42507 
│                              │                  ├ [3] : https://errata.rockylinux.org/RLSA-2026:29981 
│                              │                  ├ [4] : https://go.dev/cl/777060 
│                              │                  ├ [5] : https://go.dev/issue/79346 
│                              │                  ├ [6] : https://groups.google.com/g/golang-announce/c/tKs3rmc
│                              │                  │       BcKw 
│                              │                  ├ [7] : https://linux.oracle.com/cve/CVE-2026-42507.html 
│                              │                  ├ [8] : https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                              │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [10]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                              ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                              ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
├ [6] ╭ Target         : usr/share/grafana/bin/grafana 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ├ Packages        
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-21728 
│                       │      ├ VendorIDs        ─ [0]: GHSA-p4r4-xvrq-gvmc 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20251027
│                       │      │                  │       222923-cbe5f845dc7b 
│                       │      │                  ╰ UID : a02c5dcff632fcff 
│                       │      ├ InstalledVersion: v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ FixedVersion    : 2.8.4, 2.9.2, 2.10.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:08e96bab5f4679c5cc37eae0887125976ab722d746b18111045ed
│                       │      │                   fdfcf08a06c 
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
│                       │      ╰ LastModifiedDate: 2026-06-17T13:20:05.907Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2026-28377 
│                       │      ├ VendorIDs        ─ [0]: GHSA-ffqx-q65f-36jf 
│                       │      ├ PkgID           : github.com/grafana/tempo@v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ PkgName         : github.com/grafana/tempo 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/tempo@v1.5.1-0.20251027
│                       │      │                  │       222923-cbe5f845dc7b 
│                       │      │                  ╰ UID : a02c5dcff632fcff 
│                       │      ├ InstalledVersion: v1.5.1-0.20251027222923-cbe5f845dc7b 
│                       │      ├ FixedVersion    : 2.10.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ee4442733e3861931f7688bb2a08ff14ab6c60c6d759028fc6f3b
│                       │      │                   77528d48224 
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
│                       │      ╰ LastModifiedDate: 2026-06-17T13:20:14.76Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2026-48096 
│                       │      ├ VendorIDs        ─ [0]: GHSA-8396-jffm-qx4w 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │      │                  ╰ UID : d9f7c327b4e77cd7 
│                       │      ├ InstalledVersion: v1.14.2 
│                       │      ├ FixedVersion    : 1.16.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-48096 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:32681b12be650b9efde4b46f037a190dd0951f690ecdedaf5a3ee
│                       │      │                   69a88ed9c33 
│                       │      ├ Title           : OpenFGA: OpenFGA: Incorrect authorization due to cache key
│                       │      │                   collision in iterator caching 
│                       │      ├ Description     : OpenFGA is an authorization/permission engine built for
│                       │      │                   developers. Prior to version 1.16.0, when iterator caching
│                       │      │                   is enabled, two distinct check requests can produce the same
│                       │      │                    cache key, leading to OpenFGA reusing an earlier cached
│                       │      │                   result for a subsequent request. This issue has been patched
│                       │      │                    in version 1.16.0. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ╭ [0]: CWE-345 
│                       │      │                  ╰ [1]: CWE-668 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 5 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-48096 
│                       │      │                  ├ [1]: https://github.com/openfga/openfga 
│                       │      │                  ├ [2]: https://github.com/openfga/openfga/releases/tag/v1.16.0 
│                       │      │                  ├ [3]: https://github.com/openfga/openfga/security/advisories
│                       │      │                  │      /GHSA-8396-jffm-qx4w 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-48096 
│                       │      │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2026-48096 
│                       │      ├ PublishedDate   : 2026-06-10T16:17:09.397Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:54:51.107Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2026-55689 
│                       │      ├ VendorIDs        ─ [0]: GHSA-hcxc-wf8j-23hv 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │      │                  ╰ UID : d9f7c327b4e77cd7 
│                       │      ├ InstalledVersion: v1.14.2 
│                       │      ├ FixedVersion    : 1.18.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55689 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:5a41643b3ad80c6af40829ad172d3752e992ec25952172bca038c
│                       │      │                   cba607d054d 
│                       │      ├ Title           : OpenFGA: OIDC audience validation skipped when
│                       │      │                   --authn-oidc-audience is unset 
│                       │      ├ Description     : ## Description
│                       │      │                   
│                       │      │                   OpenFGA's OIDC authenticator skipped JWT audience (`aud`)
│                       │      │                   validation when no audience was configured.
│                       │      │                   In deployments where one identity provider issues tokens for
│                       │      │                    multiple services,
│                       │      │                   a token minted for an unrelated service could authenticate
│                       │      │                   to OpenFGA.
│                       │      │                   ## Preconditions
│                       │      │                   This applies if the following preconditions are met:
│                       │      │                   1. You run OpenFGA with `authn.method` set to `oidc`.
│                       │      │                   2. You configured `authn.oidc.issuer` but did **not** set
│                       │      │                      `authn.oidc.audience` (`--authn-oidc-audience` /
│                       │      │                   `OPENFGA_AUTHN_OIDC_AUDIENCE`).
│                       │      │                   ## Fix
│                       │      │                   Upgrade to OpenFGA 1.18.0 or greater. OpenFGA now refuses to
│                       │      │                    start in `oidc`
│                       │      │                   mode unless both `authn.oidc.issuer` and
│                       │      │                   `authn.oidc.audience` are set, and the
│                       │      │                   `aud` claim is always validated.
│                       │      │                   ## Acknowledgements
│                       │      │                   OpenFGA would like to thank https://github.com/0xVijay for
│                       │      │                   the report. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ VendorSeverity   ─ ghsa: 2 
│                       │      ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N 
│                       │      │                         ╰ V3Score : 6.8 
│                       │      ╰ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │                         ╰ [1]: https://github.com/openfga/openfga/security/advisories
│                       │                                /GHSA-hcxc-wf8j-23hv 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-55170 
│                       │      ├ VendorIDs        ─ [0]: GHSA-cf98-j28v-49v6 
│                       │      ├ PkgID           : github.com/openfga/openfga@v1.14.2 
│                       │      ├ PkgName         : github.com/openfga/openfga 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/openfga/openfga@v1.14.2 
│                       │      │                  ╰ UID : d9f7c327b4e77cd7 
│                       │      ├ InstalledVersion: v1.14.2 
│                       │      ├ FixedVersion    : 1.18.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55170 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:18a4dc56c1c178d2570a33ad14712caed3415869cecc35436b96c
│                       │      │                   d36a684730c 
│                       │      ├ Title           : OpenFGA Improper Policy Enforcement 
│                       │      ├ Description     : ## Description
│                       │      │                   
│                       │      │                   In OpenFGA, when MySQL is being used as the datastore, two
│                       │      │                   distinct check requests can return the same response.
│                       │      │                   ## Preconditions
│                       │      │                   This applies if the following preconditions are met:
│                       │      │                   1. You run OpenFGA with MySQL as the datastore
│                       │      │                   2. Your authorization decisions rely on case-sensitive user
│                       │      │                   strings.
│                       │      │                   ## Fix
│                       │      │                   Upgrade to OpenFGA 1.18.0 or greater.
│                       │      │                   ## Acknowledgements
│                       │      │                   OpenFGA would like to thank @sahajamoth for the detailed
│                       │      │                   report. 
│                       │      ├ Severity        : LOW 
│                       │      ├ VendorSeverity   ─ ghsa: 1 
│                       │      ├ CVSS             ─ ghsa ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:L/VI
│                       │      │                         │            :L/VA:N/SC:L/SI:L/SA:N 
│                       │      │                         ╰ V40Score : 2.1 
│                       │      ╰ References       ╭ [0]: https://github.com/openfga/openfga 
│                       │                         ╰ [1]: https://github.com/openfga/openfga/security/advisories
│                       │                                /GHSA-cf98-j28v-49v6 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-42151 
│                       │      ├ VendorIDs        ─ [0]: GHSA-wg65-39gg-5wfj 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.305.3 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.305.3 
│                       │      │                  ╰ UID : 83655859701a095e 
│                       │      ├ InstalledVersion: v0.305.3 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42151 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:cdf9606d7d382aaebc896ab8e4729c9158e03a491088261604340
│                       │      │                   61bb9be6d01 
│                       │      ├ Title           : github.com/prometheus/prometheus: Prometheus: Information
│                       │      │                   disclosure of Azure OAuth client secret via config API 
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
│                       │      ├ VendorSeverity   ╭ azure  : 2 
│                       │      │                  ├ bitnami: 3 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42151 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/pull/18587 
│                       │      │                  ├ [3]: https://github.com/prometheus/prometheus/pull/18590 
│                       │      │                  ├ [4]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.11.3 
│                       │      │                  ├ [5]: https://github.com/prometheus/prometheus/releases/tag/
│                       │      │                  │      v3.5.3 
│                       │      │                  ├ [6]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-wg65-39gg-5wfj 
│                       │      │                  ├ [7]: https://nvd.nist.gov/vuln/detail/CVE-2026-42151 
│                       │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-42151 
│                       │      ├ PublishedDate   : 2026-05-04T19:16:04.22Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:47:26.917Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-40179 
│                       │      ├ VendorIDs        ─ [0]: GHSA-vffh-x6r8-xx99 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.305.3 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.305.3 
│                       │      │                  ╰ UID : 83655859701a095e 
│                       │      ├ InstalledVersion: v0.305.3 
│                       │      ├ FixedVersion    : 0.311.2-0.20260410083055-07c6232d159b 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40179 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:15a9457b355e15a9a9acdf88f284b291e395a6b594c66ee286e29
│                       │      │                   4a8bc38840b 
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
│                       │      ╰ LastModifiedDate: 2026-06-17T10:44:49.617Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-44903 
│                       │      ├ VendorIDs        ─ [0]: GHSA-fw8g-cg8f-9j28 
│                       │      ├ PkgID           : github.com/prometheus/prometheus@v0.305.3 
│                       │      ├ PkgName         : github.com/prometheus/prometheus 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/prometheus/prometheus@v0.305.3 
│                       │      │                  ╰ UID : 83655859701a095e 
│                       │      ├ InstalledVersion: v0.305.3 
│                       │      ├ FixedVersion    : 0.311.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-44903 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:dcb59084c0fd84e316162340ba564bef5015165a8312359d25510
│                       │      │                   d694b2b1715 
│                       │      ├ Title           : Prometheus is an open-source monitoring system and time
│                       │      │                   series databas ... 
│                       │      ├ Description     : Prometheus is an open-source monitoring system and time
│                       │      │                   series database. From 2.49.0 to before 3.5.3 and 3.11.3, in
│                       │      │                   the Prometheus server's legacy web UI (enabled via the
│                       │      │                   command-line flag --enable-feature=old-ui), the histogram
│                       │      │                   heatmap chart view does not escape le label values when
│                       │      │                   inserting them into the HTML for use as axis tick mark
│                       │      │                   labels. An attacker who can inject crafted metrics can
│                       │      │                   execute JavaScript in the browser of any Prometheus user who
│                       │      │                    views the metric in the heatmap chart UI. This
│                       │      │                   vulnerability is fixed in 3.5.3 and 3.11.3. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ╰ nvd    : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N
│                       │      │                  │         │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                  │         ╰ V40Score : 5.1 
│                       │      │                  ├ ghsa    ╭ V3Vector : CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I
│                       │      │                  │         │            :L/A:N 
│                       │      │                  │         ├ V40Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N
│                       │      │                  │         │            /VI:N/VA:N/SC:L/SI:L/SA:N 
│                       │      │                  │         ├ V3Score  : 6.1 
│                       │      │                  │         ╰ V40Score : 5.1 
│                       │      │                  ╰ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://github.com/prometheus/prometheus 
│                       │      │                  ├ [1]: https://github.com/prometheus/prometheus/commit/38f23b
│                       │      │                  │      9075ced1de2b82d2dad8b2bebb1ecd5b7d 
│                       │      │                  ├ [2]: https://github.com/prometheus/prometheus/security/advi
│                       │      │                  │      sories/GHSA-fw8g-cg8f-9j28 
│                       │      │                  ╰ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-44903 
│                       │      ├ PublishedDate   : 2026-05-26T22:16:43.01Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:51:30.6Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-27145 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5037 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : 8da4595ba8e1b0f0 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:4e80310869bd9f5408d843b574bddbad5b6e83cca50f48eeb53ac
│                       │      │                   ee90d49d973 
│                       │      ├ Title           : *x509.Certificate).VerifyHostname previously called
│                       │      │                   matchHostnames in ... 
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
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 2 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:H 
│                       │      │                            ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/783621 
│                       │      │                  ├ [1]: https://go.dev/issue/79694 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:26:45.23Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-42504 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5038 
│                       │      ├ PkgID           : stdlib@v1.26.3 
│                       │      ├ PkgName         : stdlib 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                       │      │                  ╰ UID : 8da4595ba8e1b0f0 
│                       │      ├ InstalledVersion: v1.26.3 
│                       │      ├ FixedVersion    : 1.25.11, 1.26.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                       │      │                  │         74f5b0d61ceae5db4760 
│                       │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                       │      │                            3038e3c23fcc218cc811 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:8a269f900582d796d41902a1e913a7c5af8a15d482d26caa2dbab
│                       │      │                   f5f62d311a0 
│                       │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid enc ... 
│                       │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
│                       │      │                   invalid encoded-words can consume excessive CPU. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-407 
│                       │      ├ VendorSeverity   ╭ amazon : 3 
│                       │      │                  ╰ bitnami: 3 
│                       │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://go.dev/cl/774481 
│                       │      │                  ├ [1]: https://go.dev/issue/79217 
│                       │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                       │      │                  │      cKw 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42504 
│                       │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5038 
│                       │      ├ PublishedDate   : 2026-06-02T23:16:37.927Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:47:56.86Z 
│                       ╰ [10] ╭ VulnerabilityID : CVE-2026-42507 
│                              ├ VendorIDs        ─ [0]: GO-2026-5039 
│                              ├ PkgID           : stdlib@v1.26.3 
│                              ├ PkgName         : stdlib 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.3 
│                              │                  ╰ UID : 8da4595ba8e1b0f0 
│                              ├ InstalledVersion: v1.26.3 
│                              ├ FixedVersion    : 1.25.11, 1.26.4 
│                              ├ Status          : fixed 
│                              ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
│                              │                  │         74f5b0d61ceae5db4760 
│                              │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
│                              │                            3038e3c23fcc218cc811 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:7d8539bfb2e4fc7cc30b1a0435552d167fc333be9d9ac9e09be7d
│                              │                   34194c36969 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ amazon     : 3 
│                              │                  ├ bitnami    : 2 
│                              │                  ├ oracle-oval: 2 
│                              │                  ├ redhat     : 2 
│                              │                  ╰ rocky      : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
│                              │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                              │                  │       26-42507 
│                              │                  ├ [3] : https://errata.rockylinux.org/RLSA-2026:29981 
│                              │                  ├ [4] : https://go.dev/cl/777060 
│                              │                  ├ [5] : https://go.dev/issue/79346 
│                              │                  ├ [6] : https://groups.google.com/g/golang-announce/c/tKs3rmc
│                              │                  │       BcKw 
│                              │                  ├ [7] : https://linux.oracle.com/cve/CVE-2026-42507.html 
│                              │                  ├ [8] : https://linux.oracle.com/errata/ELSA-2026-29981.html 
│                              │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [10]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
│                              ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
│                              ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
╰ [7] ╭ Target         : usr/share/grafana/data/plugins-bundled/elasticsearch/gpx_grafana_elasticsearch_datasou
      │                  rce_linux_amd64 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ├ Packages        
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2026-39827 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5016 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39827 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:72b82da3f4cb39a79d67cc6be5ff41737079417e1a66bede0bea9
                        │      │                   1d025fef753 
                        │      ├ Title           : An authenticated SSH client that repeatedly opened channels
                        │      │                   which were ... 
                        │      ├ Description     : An authenticated SSH client that repeatedly opened channels
                        │      │                   which were rejected by the server caused unbounded memory
                        │      │                   growth, eventually crashing the server process and affecting
                        │      │                    all connected users. Rejected channels are now properly
                        │      │                   removed from the connection's internal state and released
                        │      │                   for garbage collection. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-924 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ azure : 2 
                        │      ├ References       ╭ [0]: https://go.dev/cl/781320 
                        │      │                  ├ [1]: https://go.dev/issue/35127 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39827 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5016 
                        │      ├ PublishedDate   : 2026-05-22T04:16:21.497Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.063Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2026-39828 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5014 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39828 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:70d243353745ad95307b8361b035965fec2a1a61a4f46a272c62e
                        │      │                   5e831855b4e 
                        │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh:
                        │      │                   Unauthorized command execution via discarded SSH
                        │      │                   permissions 
                        │      ├ Description     : When an SSH server authentication callback returned
                        │      │                   PartialSuccessError with non-nil Permissions, those
                        │      │                   permissions were silently discarded, potentially dropping
                        │      │                   certificate restrictions such as force-command after a
                        │      │                   second factor succeeded. Returning non-nil Permissions with
                        │      │                   PartialSuccessError now results in a connection error. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 8.8 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39828 
                        │      │                  ├ [1]: https://go.dev/cl/781621 
                        │      │                  ├ [2]: https://go.dev/issue/79562 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39828 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5014 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-39828 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.19Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.207Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2026-39829 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5018 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39829 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5b4ade46596a2d0827877d99d0f3fe9724d83e8c10ddc3c12af7a
                        │      │                   c8684635d5d 
                        │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
                        │      │                   Service via crafted public key with excessive parameters 
                        │      ├ Description     : The RSA and DSA public key parsers did not enforce size
                        │      │                   limits on key parameters. A crafted public key with an
                        │      │                   excessively large modulus or DSA parameter could cause
                        │      │                   several minutes of CPU consumption during signature
                        │      │                   verification. This could be triggered by unauthenticated
                        │      │                   clients during public key authentication. RSA moduli are now
                        │      │                    limited to 8192 bits, and DSA parameters are validated per
                        │      │                   FIPS 186-2. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-347 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ azure      : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39829 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2480681 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2480684 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
                        │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32281 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39830 
                        │      │                  ├ [20]: https://errata.almalinux.org/9/ALSA-2026-29455.html 
                        │      │                  ├ [21]: https://errata.rockylinux.org/RLSA-2026:29455 
                        │      │                  ├ [22]: https://go.dev/cl/781641 
                        │      │                  ├ [23]: https://go.dev/cl/781661 
                        │      │                  ├ [24]: https://go.dev/issue/79565 
                        │      │                  ├ [25]: https://groups.google.com/g/golang-announce/c/a082jnz
                        │      │                  │       -LvI 
                        │      │                  ├ [26]: https://linux.oracle.com/cve/CVE-2026-39829.html 
                        │      │                  ├ [27]: https://linux.oracle.com/errata/ELSA-2026-29455.html 
                        │      │                  ├ [28]: https://nvd.nist.gov/vuln/detail/CVE-2026-39829 
                        │      │                  ├ [29]: https://pkg.go.dev/vuln/GO-2026-5018 
                        │      │                  ╰ [30]: https://www.cve.org/CVERecord?id=CVE-2026-39829 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.31Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.343Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2026-39830 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5017 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39830 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8d743a5d65c3e083c86349ad187699ca11a4d04b6b258ce0ef0dc
                        │      │                   a3534b7f5c9 
                        │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh: Denial of
                        │      │                   Service via resource leak from unsolicited SSH responses 
                        │      ├ Description     : A malicious SSH peer could send unsolicited global request
                        │      │                   responses to fill an internal buffer, blocking the
                        │      │                   connection's read loop. The blocked goroutine could not be
                        │      │                   released by calling Close(), resulting in a resource leak
                        │      │                   per connection. Unsolicited global responses are now
                        │      │                   discarded. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-119 
                        │      ├ VendorSeverity   ╭ alma       : 3 
                        │      │                  ├ amazon     : 3 
                        │      │                  ├ azure      : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ├ rocky      : 3 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2026:29455 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2026-39830 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2445356 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2456333 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2456338 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2456339 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2480681 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2480684 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/show_bug.cgi?id=2445356 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/show_bug.cgi?id=2456333 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/show_bug.cgi?id=2456338 
                        │      │                  ├ [11]: https://bugzilla.redhat.com/show_bug.cgi?id=2456339 
                        │      │                  ├ [12]: https://bugzilla.redhat.com/show_bug.cgi?id=2480681 
                        │      │                  ├ [13]: https://bugzilla.redhat.com/show_bug.cgi?id=2480684 
                        │      │                  ├ [14]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-25679 
                        │      │                  ├ [15]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32280 
                        │      │                  ├ [16]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32281 
                        │      │                  ├ [17]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-32283 
                        │      │                  ├ [18]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39829 
                        │      │                  ├ [19]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       26-39830 
                        │      │                  ├ [20]: https://errata.almalinux.org/9/ALSA-2026-29455.html 
                        │      │                  ├ [21]: https://errata.rockylinux.org/RLSA-2026:29455 
                        │      │                  ├ [22]: https://github.com/golang/crypto/commit/4e7a7384ecbc8
                        │      │                  │       d519f6f4c11b36fa9d761fc8946 
                        │      │                  ├ [23]: https://go.dev/cl/781640 
                        │      │                  ├ [24]: https://go.dev/cl/781664 
                        │      │                  ├ [25]: https://go.dev/issue/79564 
                        │      │                  ├ [26]: https://groups.google.com/g/golang-announce/c/a082jnz
                        │      │                  │       -LvI 
                        │      │                  ├ [27]: https://linux.oracle.com/cve/CVE-2026-39830.html 
                        │      │                  ├ [28]: https://linux.oracle.com/errata/ELSA-2026-29455.html 
                        │      │                  ├ [29]: https://nvd.nist.gov/vuln/detail/CVE-2026-39830 
                        │      │                  ├ [30]: https://pkg.go.dev/vuln/GO-2026-5017 
                        │      │                  ├ [31]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [32]: https://ubuntu.com/security/notices/USN-8447-2 
                        │      │                  ├ [33]: https://ubuntu.com/security/notices/USN-8447-3 
                        │      │                  ╰ [34]: https://www.cve.org/CVERecord?id=CVE-2026-39830 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.44Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.483Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-39832 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5006 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39832 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8d08885c9a89d4914f720ca73fc1c914a0eae4269709df25c0ef4
                        │      │                   761d7d0b0e6 
                        │      ├ Title           : golang.org/x/crypto/ssh/agent:
                        │      │                   golang.org/x/crypto/ssh/agent: Security bypass due to
                        │      │                   improper handling of key restrictions 
                        │      ├ Description     : When adding a key to a remote agent constraint extensions
                        │      │                   such as restrict-destination-v00@openssh.com were not
                        │      │                   serialized in the request. Destination restrictions were
                        │      │                   silently stripped when forwarding keys, allowing
                        │      │                   unrestricted use of the key on the remote host. The client
                        │      │                   now serializes all constraint extensions. Additionally, the
                        │      │                   in-memory keyring returned by NewKeyring() now rejects keys
                        │      │                   with unsupported constraint extensions instead of silently
                        │      │                   ignoring them. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ├ redhat: 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.7 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39832 
                        │      │                  ├ [1]: https://github.com/golang/crypto/commit/e3d1254f1e7e60
                        │      │                  │      baa086142c46174bf6d8d0fe50 
                        │      │                  ├ [2]: https://go.dev/cl/778642 
                        │      │                  ├ [3]: https://go.dev/issue/79435 
                        │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39832 
                        │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5006 
                        │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39832 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.663Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.773Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-39835 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5015 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39835 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:22a2af4ab29168c40a4341cffb9cb795d47fb5cc73c3fa29e46e0
                        │      │                   c23128d1b43 
                        │      ├ Title           : SSH servers which use CertChecker as a public key callback
                        │      │                   without set ... 
                        │      ├ Description     : SSH servers which use CertChecker as a public key callback
                        │      │                   without setting IsUserAuthority or IsHostAuthority could be
                        │      │                   caused to panic by a client presenting a certificate.
                        │      │                   CertChecker now returns an error instead of panicking when
                        │      │                   these callbacks are nil. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ azure : 2 
                        │      ├ References       ╭ [0]: https://go.dev/cl/781660 
                        │      │                  ├ [1]: https://go.dev/issue/79563 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-39835 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5015 
                        │      ├ PublishedDate   : 2026-05-22T04:16:24.53Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:40.197Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-42508 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5021 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42508 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:2d7c23dd2770cfb26c058e9e0ffc8f00bae2a8893d55c30423faa
                        │      │                   75e0d2c1266 
                        │      ├ Title           : golang.org/x/crypto/ssh/knownhosts: golang:
                        │      │                   golang.org/x/crypto/ssh/knownhosts: Revocation bypass via
                        │      │                   unchecked SignatureKey 
                        │      ├ Description     : Previously, a revoked 'SignatureKey' belonging to a CA was
                        │      │                   not correctly checked for revocation. Now, both the 'key'
                        │      │                   and 'key.SignatureKey' are checked for @revoked. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-295 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ├ redhat: 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 7.4 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42508 
                        │      │                  ├ [1]: https://github.com/golang/crypto/commit/f717e29698a271
                        │      │                  │      c548239ed56bf5dd9516d6f7e8 
                        │      │                  ├ [2]: https://go.dev/cl/781220 
                        │      │                  ├ [3]: https://go.dev/issue/79568 
                        │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-42508 
                        │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5021 
                        │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-2 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-42508 
                        │      ├ PublishedDate   : 2026-05-22T04:16:25.44Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:57.267Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-46595 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5023 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46595 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:77e4a312ea8d350bfeedea6af3fcf6251ff8daa5085a92772f1c9
                        │      │                   d17a8541d50 
                        │      ├ Title           : golang.org/x/crypto/ssh: golang.org/x/crypto/ssh:
                        │      │                   Authorization bypass due to skipped source-address
                        │      │                   validation 
                        │      ├ Description     : Previously, CVE-2024-45337 fixed an authorization bypass for
                        │      │                    misused ssh server configurations; if any other type of
                        │      │                   callback is passed other than public key, then the
                        │      │                   source-address validation would be skipped. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-863 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ redhat: 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H
                        │      │                           │           /A:L 
                        │      │                           ╰ V3Score : 7.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46595 
                        │      │                  ├ [1]: https://github.com/golang/crypto/commit/533fb3f7e4a5ae
                        │      │                  │      23f69d1837cd851d35ff5b76ce 
                        │      │                  ├ [2]: https://go.dev/cl/781642 
                        │      │                  ├ [3]: https://go.dev/issue/79570 
                        │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-46595 
                        │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5023 
                        │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-3 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-46595 
                        │      ├ PublishedDate   : 2026-05-22T04:16:25.55Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:53:47.24Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-46597 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5013 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46597 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:29e1a2e1a3620e74aaed5ab586d9c943aa70f2713c93dad8b3a8e
                        │      │                   2609caec32f 
                        │      ├ Title           : An incorrectly placed cast from bytes to int allowed for
                        │      │                   server-side p ... 
                        │      ├ Description     : An incorrectly placed cast from bytes to int allowed for
                        │      │                   server-side panic in the AES-GCM packet decoder for
                        │      │                   well-crafted inputs. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-704 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ azure : 3 
                        │      ├ References       ╭ [0]: https://go.dev/cl/781620 
                        │      │                  ├ [1]: https://go.dev/issue/79561 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-46597 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5013 
                        │      ├ PublishedDate   : 2026-05-22T04:16:26.003Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:53:47.38Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-39831 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5019 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39831 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e81977e23569711eff74af52671e81c1614193704c8d5948e9f68
                        │      │                   a20e49088a9 
                        │      ├ Title           : The Verify() method for FIDO/U2F security key types
                        │      │                   (sk-ecdsa-sha2-nis ... 
                        │      ├ Description     : The Verify() method for FIDO/U2F security key types
                        │      │                   (sk-ecdsa-sha2-nistp256@openssh.com,
                        │      │                   sk-ssh-ed25519@openssh.com) did not check the User Presence
                        │      │                   flag. Signatures generated without physical touch were
                        │      │                   accepted, allowing unattended use of a hardware security
                        │      │                   key. To restore the previous behavior, return a
                        │      │                   "no-touch-required" extension in Permissions.Extensions from
                        │      │                    PublicKeyCallback. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-862 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/b61cf853a89d82
                        │      │                  │      cad68da5e12a6beca2116f8456 
                        │      │                  ├ [1]: https://go.dev/cl/781662 
                        │      │                  ├ [2]: https://go.dev/issue/79566 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [4]: https://pkg.go.dev/vuln/GO-2026-5019 
                        │      │                  ├ [5]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-3 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39831 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.553Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.63Z 
                        ├ [10] ╭ VulnerabilityID : CVE-2026-39833 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5005 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39833 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:84d67681525150aa20c9bf349f3d9e7aa4adf0cbd576ed7953f3f
                        │      │                   63b70ad0fd1 
                        │      ├ Title           : The in-memory keyring returned by NewKeyring() silently
                        │      │                   accepted keys  ... 
                        │      ├ Description     : The in-memory keyring returned by NewKeyring() silently
                        │      │                   accepted keys with the ConfirmBeforeUse constraint but never
                        │      │                    enforced it. The key would sign without any confirmation
                        │      │                   prompt, with no indication to the caller that the constraint
                        │      │                    was not in effect. NewKeyring() now returns an error when
                        │      │                   unsupported constraints are requested. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-862 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/0fb843a4722256
                        │      │                  │      45e917c84f1f9744757f0bab14 
                        │      │                  ├ [1]: https://go.dev/cl/778640 
                        │      │                  ├ [2]: https://go.dev/cl/778641 
                        │      │                  ├ [3]: https://go.dev/issue/79436 
                        │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39833 
                        │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5005 
                        │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-2 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39833 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.773Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.913Z 
                        ├ [11] ╭ VulnerabilityID : CVE-2026-39834 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5020 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39834 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:082ee9bf63cd082cde710a65854ad359e80cc88a75d6ddf96c2ff
                        │      │                   e0ef5570b83 
                        │      ├ Title           : When writing data larger than 4GB in a single Write call on
                        │      │                   an SSH cha ... 
                        │      ├ Description     : When writing data larger than 4GB in a single Write call on
                        │      │                   an SSH channel, an integer overflow in the internal payload
                        │      │                   size calculation caused the write loop to spin indefinitely,
                        │      │                    sending empty packets without making progress. The size
                        │      │                   comparison now uses int64 to prevent truncation. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-190 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/e052873987615d
                        │      │                  │      c96fe67607a9a6adb76311344f 
                        │      │                  ├ [1]: https://go.dev/cl/781663 
                        │      │                  ├ [2]: https://go.dev/issue/79567 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39834 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5020 
                        │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8447-2 
                        │      │                  ├ [8]: https://ubuntu.com/security/notices/USN-8447-3 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2026-39834 
                        │      ├ PublishedDate   : 2026-05-22T04:16:24.237Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:40.057Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2026-46598 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5033 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46598 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cd9537a0b3935dd139c4874bcbd9087ace6ef415f5b6f5232f81e
                        │      │                   c3dc5ea20ed 
                        │      ├ Title           : golang.org/x/crypto/ssh/agent: golang:
                        │      │                   golang.org/x/crypto/ssh/agent: Denial of Service via
                        │      │                   malformed input 
                        │      ├ Description     : For certain crafted inputs, a 'ed25519.PrivateKey' was
                        │      │                   created by casting malformed wire bytes, leading to a panic
                        │      │                   when used. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-129 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 2 
                        │      │                  ╰ redhat: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:L 
                        │      │                           ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-46598 
                        │      │                  ├ [1]: https://go.dev/cl/781360 
                        │      │                  ├ [2]: https://go.dev/issue/79596 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-46598 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5033 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-46598 
                        │      ├ PublishedDate   : 2026-05-22T04:16:26.537Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:53:47.52Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2026-25680 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5028 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f753172f76baf50b8c49be0911beef36ace1bf68b5700d59cbb74
                        │      │                   27554437373 
                        │      ├ Title           : Parsing arbitrary HTML can consume excessive CPU time,
                        │      │                   possibly leadin ... 
                        │      ├ Description     : Parsing arbitrary HTML can consume excessive CPU time,
                        │      │                   possibly leading to denial of service. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-400 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ azure : 2 
                        │      ├ References       ╭ [0]: https://go.dev/cl/781702 
                        │      │                  ├ [1]: https://go.dev/issue/79573 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-25680 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5028 
                        │      ├ PublishedDate   : 2026-05-22T16:16:19.753Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:25:03.14Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2026-25681 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5029 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4b8edce6f9926affdd0d410c52563fb44c2621efb8ec16037a7a1
                        │      │                   fbe5f84e1c1 
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
                        │      ├ References       ╭ [0]: https://go.dev/cl/781703 
                        │      │                  ├ [1]: https://go.dev/issue/79574 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-25681 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5029 
                        │      ├ PublishedDate   : 2026-05-22T16:16:19.863Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:25:03.343Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2026-27136 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5030 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d3e59c7e8012b24568cc82c5b7cde8cb96584b976e6fbaa2cf7dc
                        │      │                   86451e2f4da 
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
                        │      ├ References       ╭ [0]: https://go.dev/cl/781685 
                        │      │                  ├ [1]: https://go.dev/issue/79575 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27136 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5030 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.087Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:26:43.803Z 
                        ├ [16] ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.53.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:727eb044f54ca56b57270eedddddf7d7636ac0a2f140c159f1130
                        │      │                   5887ece0ae4 
                        │      ├ Title           : net/http/internal/http2: golang: golang.org/x/net: Go
                        │      │                   HTTP/2: Denial of Service via malformed
                        │      │                   SETTINGS_MAX_FRAME_SIZE frame 
                        │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infinite loop of writing CONTINUATION frames if it
                        │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [1] : https://github.com/golang/go/issues/78476 
                        │      │                  ├ [2] : https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [3] : https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [4] : https://go.dev/cl/761581 
                        │      │                  ├ [5] : https://go.dev/cl/761640 
                        │      │                  ├ [6] : https://go.dev/issue/78476 
                        │      │                  ├ [7] : https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [8] : https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [9] : https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [10]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [11]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [12]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [13]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [14]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [15]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:38:08.657Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2026-39821 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5026 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:36b18abd59379eed307566fc952f6b1419d316f2735e85add0519
                        │      │                   fc39b83ce76 
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
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 4 
                        │      │                  ├ redhat: 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 8.2 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39821 
                        │      │                  ├ [1]: https://github.com/golang/go/issues/78760 
                        │      │                  ├ [2]: https://go.dev/cl/767220 
                        │      │                  ├ [3]: https://go.dev/issue/78760 
                        │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39821 
                        │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5026 
                        │      │                  ├ [7]: https://ubuntu.com/security/notices/USN-8416-1 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-39821 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.41Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.333Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2026-42502 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5027 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:39b5d403dbb3791792ccb5f2f1f3dcec3cc93e343c2513946c722
                        │      │                   dfd9d2d650a 
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
                        ├ [19] ╭ VulnerabilityID : CVE-2026-42506 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5025 
                        │      ├ PkgID           : golang.org/x/net@v0.52.0 
                        │      ├ PkgName         : golang.org/x/net 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/net@v0.52.0 
                        │      │                  ╰ UID : 1328e6f059faf6ba 
                        │      ├ InstalledVersion: v0.52.0 
                        │      ├ FixedVersion    : 0.55.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:31db1fa312a3cf949d2431d2326eed8d9e519a34cc629dc28a327
                        │      │                   9fd6c27bcdb 
                        │      ├ Title           : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result  ... 
                        │      ├ Description     : Parsing arbitrary HTML which is then rendered using Render
                        │      │                   can result in an unexpected HTML tree. This can be leveraged
                        │      │                    to execute XSS attacks in applications that attempt to
                        │      │                   sanitize input HTML before rendering. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ╰ azure : 2 
                        │      ├ References       ╭ [0]: https://go.dev/cl/781700 
                        │      │                  ├ [1]: https://go.dev/issue/79571 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/iI-mYSI0
                        │      │                  │      lu8 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-42506 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5025 
                        │      ├ PublishedDate   : 2026-05-22T16:16:20.803Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.993Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2026-39824 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5024 
                        │      ├ PkgID           : golang.org/x/sys@v0.42.0 
                        │      ├ PkgName         : golang.org/x/sys 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/sys@v0.42.0 
                        │      │                  ╰ UID : a4f49328d372b936 
                        │      ├ InstalledVersion: v0.42.0 
                        │      ├ FixedVersion    : 0.44.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:5308bc39d02c44c2f85c303ee3b15491b2932936ca65014c5f9d9
                        │      │                   1dad289dedb 
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
                        ├ [21] ╭ VulnerabilityID : CVE-2026-27145 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5037 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:157f04eee93ebfe92e999945057b5ce772cf9f62f860d1d5bfb65
                        │      │                   639bf073b84 
                        │      ├ Title           : *x509.Certificate).VerifyHostname previously called
                        │      │                   matchHostnames in ... 
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
                        │      ├ VendorSeverity   ╭ amazon : 3 
                        │      │                  ╰ bitnami: 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           L/A:H 
                        │      │                            ╰ V3Score : 6.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/783621 
                        │      │                  ├ [1]: https://go.dev/issue/79694 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                        │      │                  │      cKw 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2026-27145 
                        │      │                  ╰ [4]: https://pkg.go.dev/vuln/GO-2026-5037 
                        │      ├ PublishedDate   : 2026-06-02T23:16:35.57Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:26:45.23Z 
                        ├ [22] ╭ VulnerabilityID : CVE-2026-33811 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4981 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4e4267fbfa3fab8d5b424e368586de126c58c1d247b5ed8eee123
                        │      │                   167ffbfaad5 
                        │      ├ Title           : net: golang: Go net package: Denial of Service via long
                        │      │                   CNAME response in LookupCNAME 
                        │      ├ Description     : When using LookupCNAME with the cgo DNS resolver, a very
                        │      │                   long CNAME response can trigger a double-free of C memory
                        │      │                   and a crash. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-415 
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
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-33811 
                        │      │                  ├ [1]: https://go.dev/cl/767860 
                        │      │                  ├ [2]: https://go.dev/issue/78803 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2026-33811.html 
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2026-33811 
                        │      │                  ├ [7]: https://pkg.go.dev/vuln/GO-2026-4981 
                        │      │                  ╰ [8]: https://www.cve.org/CVERecord?id=CVE-2026-33811 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.77Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:38:08.167Z 
                        ├ [23] ╭ VulnerabilityID : CVE-2026-33814 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4918 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:233521c36d7f4c3e3e4c84ed9512c395f8f348aa327ecfd4c7cae
                        │      │                   0c60195709c 
                        │      ├ Title           : net/http/internal/http2: golang: golang.org/x/net: Go
                        │      │                   HTTP/2: Denial of Service via malformed
                        │      │                   SETTINGS_MAX_FRAME_SIZE frame 
                        │      ├ Description     : When processing HTTP/2 SETTINGS frames, transport will enter
                        │      │                    an infinite loop of writing CONTINUATION frames if it
                        │      │                   receives a SETTINGS_MAX_FRAME_SIZE with a value of 0. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-835 
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
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-33814 
                        │      │                  ├ [1] : https://github.com/golang/go/issues/78476 
                        │      │                  ├ [2] : https://go-review.googlesource.com/c/go/+/761581 
                        │      │                  ├ [3] : https://go-review.googlesource.com/c/net/+/761640 
                        │      │                  ├ [4] : https://go.dev/cl/761581 
                        │      │                  ├ [5] : https://go.dev/cl/761640 
                        │      │                  ├ [6] : https://go.dev/issue/78476 
                        │      │                  ├ [7] : https://groups.google.com/g/golang-announce/c/qcCIEXs
                        │      │                  │       o47M 
                        │      │                  ├ [8] : https://linux.oracle.com/cve/CVE-2026-33814.html 
                        │      │                  ├ [9] : https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [10]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [11]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [12]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ├ [13]: https://ubuntu.com/security/notices/USN-8471-1 
                        │      │                  ├ [14]: https://ubuntu.com/security/notices/USN-8472-1 
                        │      │                  ├ [15]: https://ubuntu.com/security/notices/USN-8473-1 
                        │      │                  ╰ [16]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
                        │      ├ PublishedDate   : 2026-05-07T20:16:42.88Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:38:08.657Z 
                        ├ [24] ╭ VulnerabilityID : CVE-2026-39820 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4986 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:d0e33c6755d1e0bde4f16e8013e2dbf4e84282f5582c5766144cd
                        │      │                   3aa4111d233 
                        │      ├ Title           : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and Parse ... 
                        │      ├ Description     : Well-crafted inputs reaching ParseAddress, ParseAddressList,
                        │      │                    and ParseDate were able to trigger excessive CPU exhaustion
                        │      │                    and memory allocations. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-770 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 3 
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
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39820.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4986 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.193Z 
                        ├ [25] ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8652a943a3af6b52b3df395050e9773dd4de9efea64da1e15698d
                        │      │                   e00debb309f 
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
                        ├ [26] ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:07a8c6e7e7b98edc281778f144f6ca099afe1aa9a95ab8ec2a0a3
                        │      │                   babe19dbb89 
                        │      ├ Title           : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing ... 
                        │      ├ Description     : Pathological inputs could cause DoS through consumePhrase
                        │      │                   when parsing an email address according to RFC 5322. 
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 3 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://go.dev/cl/771520 
                        │      │                  ├ [1]: https://go.dev/issue/78987 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-42499.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22121.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.183Z 
                        ├ [27] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:79a5b270b2bfbb2d57aee4e390b683c4963338be9fc9a7acb9e66
                        │      │                   11974240610 
                        │      ├ Title           : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid enc ... 
                        │      ├ Description     : Decoding a maliciously-crafted MIME header containing many
                        │      │                   invalid encoded-words can consume excessive CPU. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-407 
                        │      ├ VendorSeverity   ╭ amazon : 3 
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
                        ├ [28] ╭ VulnerabilityID : CVE-2026-39823 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4982 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:fc76c65d37e20d49dcdecc182aced1b33db7323bc4ca8e60ad4c4
                        │      │                   dd3f2b6ef0d 
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
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:22aa4e9a243e8fd9954df632f417384aec3134a689b0acf31696b
                        │      │                   3de9ad483d8 
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
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                        │      │                  │         74f5b0d61ceae5db4760 
                        │      │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                        │      │                            3038e3c23fcc218cc811 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:b0c913af7c2ee5f5e69800345347dc23b3c0c892121e640328811
                        │      │                   aa3ee7e8353 
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
                        ╰ [31] ╭ VulnerabilityID : CVE-2026-42507 
                               ├ VendorIDs        ─ [0]: GO-2026-5039 
                               ├ PkgID           : stdlib@v1.26.2 
                               ├ PkgName         : stdlib 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                               │                  ╰ UID : 83c42d84cdb2ccfe 
                               ├ InstalledVersion: v1.26.2 
                               ├ FixedVersion    : 1.25.11, 1.26.4 
                               ├ Status          : fixed 
                               ├ Layer            ╭ Digest: sha256:c02ebffdd3dff486c0991afedd559426b15ac728dcdd
                               │                  │         74f5b0d61ceae5db4760 
                               │                  ╰ DiffID: sha256:dc237a9aa618b60d4a51b91153000f2b93715c12214d
                               │                            3038e3c23fcc218cc811 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:e4fe8f9a576400ff402b96ddcad1467917cee97e70a9bdddbb007
                               │                   4812aa50f41 
                               ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                               │                   error messages via input injection 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : MEDIUM 
                               ├ VendorSeverity   ╭ amazon     : 3 
                               │                  ├ bitnami    : 2 
                               │                  ├ oracle-oval: 2 
                               │                  ├ redhat     : 2 
                               │                  ╰ rocky      : 2 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 5.3 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                            │           L/A:N 
                               │                            ╰ V3Score : 5.3 
                               ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-42507 
                               │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=2484205 
                               │                  ├ [2] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                               │                  │       26-42507 
                               │                  ├ [3] : https://errata.rockylinux.org/RLSA-2026:29981 
                               │                  ├ [4] : https://go.dev/cl/777060 
                               │                  ├ [5] : https://go.dev/issue/79346 
                               │                  ├ [6] : https://groups.google.com/g/golang-announce/c/tKs3rmc
                               │                  │       BcKw 
                               │                  ├ [7] : https://linux.oracle.com/cve/CVE-2026-42507.html 
                               │                  ├ [8] : https://linux.oracle.com/errata/ELSA-2026-29981.html 
                               │                  ├ [9] : https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                               │                  ├ [10]: https://pkg.go.dev/vuln/GO-2026-5039 
                               │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
```

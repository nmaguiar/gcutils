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
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54512 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:7e64d2b7c4717fda710ac084984cd09242bafe565ef09b38710ab1
│                       │     │                   81a08c53d5 
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
│                       │     ╰ LastModifiedDate: 2026-06-24T16:16:32.5Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54513 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:ef2f57935ab2f9cb5a0f034a518f5654bbff48461857d2bf3ccc6e
│                       │     │                   4555830a21 
│                       │     ├ Title           : jackson-databind contains the general-purpose data-binding
│                       │     │                   functionali ... 
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
│                       │     ├ VendorSeverity   ─ ghsa: 3 
│                       │     ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H 
│                       │     │                         ╰ V3Score : 8.1 
│                       │     ├ References       ╭ [0]: https://github.com/FasterXML/jackson-databind 
│                       │     │                  ├ [1]: https://github.com/FasterXML/jackson-databind/commit/01
│                       │     │                  │      d1692c8d0ed03e51a0e3c4f8a9e6908e4931e5 
│                       │     │                  ├ [2]: https://github.com/FasterXML/jackson-databind/commit/24
│                       │     │                  │      529da29fdf46ff94ca38de9ebf31cd188f5e8e 
│                       │     │                  ├ [3]: https://github.com/FasterXML/jackson-databind/issues/5981 
│                       │     │                  ├ [4]: https://github.com/FasterXML/jackson-databind/issues/5983 
│                       │     │                  ├ [5]: https://github.com/FasterXML/jackson-databind/pull/5984 
│                       │     │                  ╰ [6]: https://github.com/FasterXML/jackson-databind/security/
│                       │     │                         advisories/GHSA-rmj7-2vxq-3g9f 
│                       │     ├ PublishedDate   : 2026-06-23T21:17:02.333Z 
│                       │     ╰ LastModifiedDate: 2026-06-24T16:16:32.6Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54514 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:d599d334ba47635bdc21496be16fac9dd38dfd1e82112be9936ef9
│                       │     │                   246d723fb6 
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
│                       │     ╰ LastModifiedDate: 2026-06-23T21:17:02.467Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54515 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:872ce355487a3270f1fca50a21fef7acc93594d7cd971c8cd9e4ca
│                       │     │                   205d1dd9c8 
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
│                       │     ╰ LastModifiedDate: 2026-06-24T13:16:32.653Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54516 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:32e854f9ca0afd401eee0f07f660cd9a721a557690a58ad70deec3
│                       │     │                   a5330df07b 
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
│                       │     ╰ LastModifiedDate: 2026-06-24T14:17:33.547Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                       │     │                  │         8e6f99dad39e14a2ece 
│                       │     │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                       │     │                            91cc80e810a1d1c4bb6 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54517 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Maven 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Amaven 
│                       │     ├ Fingerprint     : sha256:bbdb01867e2144d72defaaf127645283587962316071110d9c8905
│                       │     │                   8840dc23bc 
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
│                       │     ╰ LastModifiedDate: 2026-06-24T20:16:33Z 
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
│                             ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea10
│                             │                  │         8e6f99dad39e14a2ece 
│                             │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b7
│                             │                            91cc80e810a1d1c4bb6 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-54518 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Fingerprint     : sha256:6d5f979e4be2628a3b2f8461e6ecb4677c92d70e731024e3c4ffcf
│                             │                   ec01d6383a 
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
│                             ╰ LastModifiedDate: 2026-06-24T17:17:29.163Z 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39827 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:48048eda3cd113eeb5f10d91fc9abbf43acd42a903d932a60ecd3
│                       │      │                   82668899db0 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39828 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:a8080d8c16a2e46449413aa38d95f63ffc29d927ee30c63263317
│                       │      │                   013782ab62c 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39829 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:5e66ab605f36493b1ffa36d6be09101c6db71276cf2903d4f4482
│                       │      │                   c84b7244464 
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
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39829 
│                       │      │                  ├ [1]: https://go.dev/cl/781641 
│                       │      │                  ├ [2]: https://go.dev/cl/781661 
│                       │      │                  ├ [3]: https://go.dev/issue/79565 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39829 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5018 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39829 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39830 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:37fb8dd8fd6ab93e3267e8601334b50a3d6ec11f032d8d768f1c5
│                       │      │                   f3044dc89a9 
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
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-39830 
│                       │      │                  ├ [1] : https://github.com/golang/crypto/commit/4e7a7384ecbc8
│                       │      │                  │       d519f6f4c11b36fa9d761fc8946 
│                       │      │                  ├ [2] : https://go.dev/cl/781640 
│                       │      │                  ├ [3] : https://go.dev/cl/781664 
│                       │      │                  ├ [4] : https://go.dev/issue/79564 
│                       │      │                  ├ [5] : https://groups.google.com/g/golang-announce/c/a082jnz
│                       │      │                  │       -LvI 
│                       │      │                  ├ [6] : https://nvd.nist.gov/vuln/detail/CVE-2026-39830 
│                       │      │                  ├ [7] : https://pkg.go.dev/vuln/GO-2026-5017 
│                       │      │                  ├ [8] : https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [9] : https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ├ [10]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-39830 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.483Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39835 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5015 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39835 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:6f5fbc5eebed145cb982d5907c3d4302024e3e0ecbf73af1f7b8b
│                       │      │                   6e506c5fe5a 
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
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-42508 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5021 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42508 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:96753eb6be5aa77247aeb1188a3d4dbb36f5ab1965e35e4b62083
│                       │      │                   dff54bcd0e7 
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
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-46595 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5023 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46595 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:c8f245009aa7741fe64855093e2e7622234b10be871a16296e887
│                       │      │                   574a6a9f36b 
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
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-46597 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5013 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46597 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:620ec20148581fb80b723d766f367e4ea8ac5699dd6e8d3f45c95
│                       │      │                   e29d01ec9e2 
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
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-39831 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5019 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39831 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b0623696c50bdc98df5d9a860bd6c0c71b192ca0ebc75aa428480
│                       │      │                   4f498387b71 
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
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-39832 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5006 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39832 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:2d1e18631f01a7591249fab8da31ee3aab796bc1ed76b49b23d1f
│                       │      │                   558106992e3 
│                       │      ├ Title           : When adding a key to a remote agent constraint extensions
│                       │      │                   such as rest ... 
│                       │      ├ Description     : When adding a key to a remote agent constraint extensions
│                       │      │                   such as restrict-destination-v00@openssh.com were not
│                       │      │                   serialized in the request. Destination restrictions were
│                       │      │                   silently stripped when forwarding keys, allowing
│                       │      │                   unrestricted use of the key on the remote host. The client
│                       │      │                   now serializes all constraint extensions. Additionally, the
│                       │      │                   in-memory keyring returned by NewKeyring() now rejects keys
│                       │      │                   with unsupported constraint extensions instead of silently
│                       │      │                   ignoring them. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-502 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/e3d1254f1e7e60
│                       │      │                  │      baa086142c46174bf6d8d0fe50 
│                       │      │                  ├ [1]: https://go.dev/cl/778642 
│                       │      │                  ├ [2]: https://go.dev/issue/79435 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39832 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5006 
│                       │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39832 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.663Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.773Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-39833 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5005 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 4761af9aeb1b917b 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39833 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:86f6979b1d27398c6f6d0122fee24043460f55d8ffdb324f26dbd
│                       │      │                   bb83f494aea 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39834 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:e4abfc878b6001d0dcb7a4f2ab786d94fc8cf6aefffaa4fa0352d
│                       │      │                   9563bd97dbf 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46598 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:3e367a3207564e2c8b5b29b3c10b8b511552428a34acf49b34314
│                       │      │                   a29ab40173a 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:e3b0c3d630e4bc2c18a5ad7a62da03ad28479384bb87eeecc4a62
│                       │      │                   13dfd4af10f 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:8092ba019a699f73311746f9a6c8ce00c40014ed0c41fe19610af
│                       │      │                   b01f314a435 
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
│                              ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                              │                  │         08e6f99dad39e14a2ece 
│                              │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                              │                            791cc80e810a1d1c4bb6 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:f4baeb6762729fbb0c77277345caee10cdc598444cfd408c268fd
│                              │                   1dcb133910f 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ amazon : 3 
│                              │                  ├ bitnami: 2 
│                              │                  ╰ redhat : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1]: https://go.dev/cl/777060 
│                              │                  ├ [2]: https://go.dev/issue/79346 
│                              │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                              │                  │      cKw 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39827 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b4644c0c75def2a226b0eb1d43e009bc92bed685b70ee0d508107
│                       │      │                   6c267d2a5df 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39828 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:b0d5a663149ab09d0cf91bd2879189391fad2a1306e8208a2f0ce
│                       │      │                   88d2bc587a9 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39829 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:926acb8d854978fadb70a0304a4080dff18d83295a159c2c624b4
│                       │      │                   0d872f71edd 
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
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ redhat: 3 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39829 
│                       │      │                  ├ [1]: https://go.dev/cl/781641 
│                       │      │                  ├ [2]: https://go.dev/cl/781661 
│                       │      │                  ├ [3]: https://go.dev/issue/79565 
│                       │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39829 
│                       │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5018 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39829 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39830 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:638be9f82c8ed002bde58933802cdcc3d6f1ab5a50e384a80553f
│                       │      │                   6259b77b90c 
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
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ├ redhat: 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
│                       │      │                           │           /A:H 
│                       │      │                           ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-39830 
│                       │      │                  ├ [1] : https://github.com/golang/crypto/commit/4e7a7384ecbc8
│                       │      │                  │       d519f6f4c11b36fa9d761fc8946 
│                       │      │                  ├ [2] : https://go.dev/cl/781640 
│                       │      │                  ├ [3] : https://go.dev/cl/781664 
│                       │      │                  ├ [4] : https://go.dev/issue/79564 
│                       │      │                  ├ [5] : https://groups.google.com/g/golang-announce/c/a082jnz
│                       │      │                  │       -LvI 
│                       │      │                  ├ [6] : https://nvd.nist.gov/vuln/detail/CVE-2026-39830 
│                       │      │                  ├ [7] : https://pkg.go.dev/vuln/GO-2026-5017 
│                       │      │                  ├ [8] : https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ├ [9] : https://ubuntu.com/security/notices/USN-8447-2 
│                       │      │                  ├ [10]: https://ubuntu.com/security/notices/USN-8447-3 
│                       │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-39830 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.44Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.483Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2026-39835 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5015 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39835 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:84d593b6391f78ffc71196fdf43351fb917e1d860a00c07c75cc2
│                       │      │                   e8328f99cb2 
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
│                       ├ [5]  ╭ VulnerabilityID : CVE-2026-42508 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5021 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42508 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:55ba515d63bd6b5e67b3abea91bb04ff0fc5f06bfc8f502a71dfa
│                       │      │                   0caf80a04d4 
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
│                       ├ [6]  ╭ VulnerabilityID : CVE-2026-46595 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5023 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46595 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:aa15bb8943dad0eb7b6b4b471de86f3186acfa3bfa5fc3eaa8260
│                       │      │                   21711124306 
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
│                       ├ [7]  ╭ VulnerabilityID : CVE-2026-46597 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5013 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46597 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:54bf254e6ef5e9f579e114e5862db8e197608fe63683128d8706e
│                       │      │                   a4848fc479f 
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
│                       ├ [8]  ╭ VulnerabilityID : CVE-2026-39831 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5019 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39831 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:df4436a72cb68cddbd774cb8ee22c33fcbc323bca41057ed2973d
│                       │      │                   2850b809b6f 
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
│                       ├ [9]  ╭ VulnerabilityID : CVE-2026-39832 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5006 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39832 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:fed69c01c5ad9ace60add244d314d9b995d11ba1b41df4a2e9ad7
│                       │      │                   ec1d0ba883f 
│                       │      ├ Title           : When adding a key to a remote agent constraint extensions
│                       │      │                   such as rest ... 
│                       │      ├ Description     : When adding a key to a remote agent constraint extensions
│                       │      │                   such as restrict-destination-v00@openssh.com were not
│                       │      │                   serialized in the request. Destination restrictions were
│                       │      │                   silently stripped when forwarding keys, allowing
│                       │      │                   unrestricted use of the key on the remote host. The client
│                       │      │                   now serializes all constraint extensions. Additionally, the
│                       │      │                   in-memory keyring returned by NewKeyring() now rejects keys
│                       │      │                   with unsupported constraint extensions instead of silently
│                       │      │                   ignoring them. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-502 
│                       │      ├ VendorSeverity   ╭ amazon: 3 
│                       │      │                  ├ azure : 3 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/e3d1254f1e7e60
│                       │      │                  │      baa086142c46174bf6d8d0fe50 
│                       │      │                  ├ [1]: https://go.dev/cl/778642 
│                       │      │                  ├ [2]: https://go.dev/issue/79435 
│                       │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
│                       │      │                  │      LvI 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39832 
│                       │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5006 
│                       │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-1 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39832 
│                       │      ├ PublishedDate   : 2026-05-22T04:16:22.663Z 
│                       │      ╰ LastModifiedDate: 2026-06-17T10:42:39.773Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2026-39833 
│                       │      ├ VendorIDs        ─ [0]: GO-2026-5005 
│                       │      ├ PkgID           : golang.org/x/crypto@v0.51.0 
│                       │      ├ PkgName         : golang.org/x/crypto 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.51.0 
│                       │      │                  ╰ UID : 21928f0e2b53c1f3 
│                       │      ├ InstalledVersion: v0.51.0 
│                       │      ├ FixedVersion    : 0.52.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39833 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:9618b39db2ef95307a739b4982a8bfab0b89eba5fccf364a8e36a
│                       │      │                   2b8ea21ef5a 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39834 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:0fa9f7c92ee7beed98dbe7c6fcee824d7e0a24a6ba8e3764fda8b
│                       │      │                   b7f8b57706d 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46598 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:51c2e6ada2dab15a04e5409e6aeef2c1a87b6732f690d6e4f83db
│                       │      │                   0f35ef27b19 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:9e3a1501f64ef6684beb3c593d525e9fcd249fa1c01e5d452c94f
│                       │      │                   a741121ad50 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:a81dc15ef65f20d4c1460064d13d3c4872e8618472600c7a40e2d
│                       │      │                   cb8253dd494 
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
│                              ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                              │                  │         08e6f99dad39e14a2ece 
│                              │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                              │                            791cc80e810a1d1c4bb6 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:2792dc455324df416e393bd4b9153e216abd029c1c667f6e3ddcd
│                              │                   9e301c14bf7 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ amazon : 3 
│                              │                  ├ bitnami: 2 
│                              │                  ╰ redhat : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1]: https://go.dev/cl/777060 
│                              │                  ├ [2]: https://go.dev/issue/79346 
│                              │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                              │                  │      cKw 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-21728 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:e2f501ed7e10f2c21f691d28bbbfb9e7aa0f0a505e5fc00f20b3f
│                       │      │                   69d11ec2d73 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-28377 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:9654cc8c83e859db1c5dcafad86264a00e5a3705049679ac2ed3b
│                       │      │                   1473c86c74e 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-48096 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:b1c3affd8216770a6598fed54db3a5aa0bd29bc0d8e8bb1743c31
│                       │      │                   cbcfd3e5e3a 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55689 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:95966c37654ebeaeb841e160eaa6fb94379bcb54dc7c533cd4f01
│                       │      │                   a056fc25326 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-55170 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ee39e7ff603b37509081bc07801b9e399c468dc370f552e826726
│                       │      │                   00173d573eb 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42151 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:ac6f3b52a553d9011ea94821d8ac70e27f1663f9a5fd78287e9cf
│                       │      │                   b9b49946fad 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-40179 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:997ed984c8b63a66990679a498546d1673c9a7a92d53f7f732bd0
│                       │      │                   11e80e9bbdb 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-44903 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Fingerprint     : sha256:a0a3a4e0bf85bd52aeb2078fa247ef15297a4e4642dc5bd6d1e41
│                       │      │                   32fff9a0d7f 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:cb7075a5fead6d186ea23551f85810d25a1630fe6d01c9577f93f
│                       │      │                   d1ab3a7b748 
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
│                       │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                       │      │                  │         08e6f99dad39e14a2ece 
│                       │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                       │      │                            791cc80e810a1d1c4bb6 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
│                       │      ├ DataSource       ╭ ID  : govulndb 
│                       │      │                  ├ Name: The Go Vulnerability Database 
│                       │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                       │      ├ Fingerprint     : sha256:e8647c2e6296e737f3ba04352ca5fc3b68d766555cac30888045c
│                       │      │                   cff832c57ca 
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
│                              ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
│                              │                  │         08e6f99dad39e14a2ece 
│                              │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
│                              │                            791cc80e810a1d1c4bb6 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
│                              ├ DataSource       ╭ ID  : govulndb 
│                              │                  ├ Name: The Go Vulnerability Database 
│                              │                  ╰ URL : https://pkg.go.dev/vuln/ 
│                              ├ Fingerprint     : sha256:aea1bf4aead9234786e1dc0e30413101ceb16cbb4ff3de519c218
│                              │                   75386633df9 
│                              ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
│                              │                   error messages via input injection 
│                              ├ Description     : When returning errors, functions in the net/textproto
│                              │                   package would include its input as part of the error. This
│                              │                   might allow an attacker to inject misleading content to
│                              │                   errors that are printed or logged. 
│                              ├ Severity        : MEDIUM 
│                              ├ VendorSeverity   ╭ amazon : 3 
│                              │                  ├ bitnami: 2 
│                              │                  ╰ redhat : 2 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 5.3 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 5.3 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
│                              │                  ├ [1]: https://go.dev/cl/777060 
│                              │                  ├ [2]: https://go.dev/issue/79346 
│                              │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
│                              │                  │      cKw 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
│                              │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
│                              │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39827 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:100d9018f6d53344c6f8b433a4c7cc47cdf6cf00e084aaca02e6e
                        │      │                   b0c0a46d948 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39828 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:e753c17c33cc0dfde7fbf5f7bdabccbf44dce3ea4fdbc1f573d02
                        │      │                   99f8a8bca63 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39829 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:373355b22259b407db874c99fc3b83d98f17a29de21763a65fec3
                        │      │                   4731d10227f 
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
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ╰ redhat: 3 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-39829 
                        │      │                  ├ [1]: https://go.dev/cl/781641 
                        │      │                  ├ [2]: https://go.dev/cl/781661 
                        │      │                  ├ [3]: https://go.dev/issue/79565 
                        │      │                  ├ [4]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39829 
                        │      │                  ├ [6]: https://pkg.go.dev/vuln/GO-2026-5018 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39829 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39830 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:1827da21ed04a53d2e8a8182a166850eee0e087289dce8b47ec51
                        │      │                   4388a2b1b7f 
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
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ├ redhat: 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ─ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N
                        │      │                           │           /A:H 
                        │      │                           ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2026-39830 
                        │      │                  ├ [1] : https://github.com/golang/crypto/commit/4e7a7384ecbc8
                        │      │                  │       d519f6f4c11b36fa9d761fc8946 
                        │      │                  ├ [2] : https://go.dev/cl/781640 
                        │      │                  ├ [3] : https://go.dev/cl/781664 
                        │      │                  ├ [4] : https://go.dev/issue/79564 
                        │      │                  ├ [5] : https://groups.google.com/g/golang-announce/c/a082jnz
                        │      │                  │       -LvI 
                        │      │                  ├ [6] : https://nvd.nist.gov/vuln/detail/CVE-2026-39830 
                        │      │                  ├ [7] : https://pkg.go.dev/vuln/GO-2026-5017 
                        │      │                  ├ [8] : https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ├ [9] : https://ubuntu.com/security/notices/USN-8447-2 
                        │      │                  ├ [10]: https://ubuntu.com/security/notices/USN-8447-3 
                        │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2026-39830 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.44Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.483Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2026-39835 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5015 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39835 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:6faeb33331c5789b102f59bfd51b7ce2d8143db50a272dcc4c6ee
                        │      │                   3c653c34147 
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
                        ├ [5]  ╭ VulnerabilityID : CVE-2026-42508 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5021 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42508 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:31a615ac470d4059e7445693ef830fb19afdf86cbc4418ce90181
                        │      │                   492f289e088 
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
                        ├ [6]  ╭ VulnerabilityID : CVE-2026-46595 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5023 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46595 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7161d64578aab4c6b0beea8e105dfc6037d28ba750be0b0ae4446
                        │      │                   04471f5301f 
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
                        ├ [7]  ╭ VulnerabilityID : CVE-2026-46597 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5013 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46597 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:f2c2b3844480ab3dbe8e0cdd71d04e20aac7a94966d3968392bef
                        │      │                   ea7473e3f8c 
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
                        ├ [8]  ╭ VulnerabilityID : CVE-2026-39831 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5019 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39831 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:ae579f7aad0b8100994f956a539b3d50d8de411adb72d873194ca
                        │      │                   bbc0c629f7c 
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
                        ├ [9]  ╭ VulnerabilityID : CVE-2026-39832 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5006 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39832 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:dc03d3a4fe99290c1bd38ff55e186f6d196367b7e1678b68221ad
                        │      │                   b2d8b157f61 
                        │      ├ Title           : When adding a key to a remote agent constraint extensions
                        │      │                   such as rest ... 
                        │      ├ Description     : When adding a key to a remote agent constraint extensions
                        │      │                   such as restrict-destination-v00@openssh.com were not
                        │      │                   serialized in the request. Destination restrictions were
                        │      │                   silently stripped when forwarding keys, allowing
                        │      │                   unrestricted use of the key on the remote host. The client
                        │      │                   now serializes all constraint extensions. Additionally, the
                        │      │                   in-memory keyring returned by NewKeyring() now rejects keys
                        │      │                   with unsupported constraint extensions instead of silently
                        │      │                   ignoring them. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-502 
                        │      ├ VendorSeverity   ╭ amazon: 3 
                        │      │                  ├ azure : 3 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ References       ╭ [0]: https://github.com/golang/crypto/commit/e3d1254f1e7e60
                        │      │                  │      baa086142c46174bf6d8d0fe50 
                        │      │                  ├ [1]: https://go.dev/cl/778642 
                        │      │                  ├ [2]: https://go.dev/issue/79435 
                        │      │                  ├ [3]: https://groups.google.com/g/golang-announce/c/a082jnz-
                        │      │                  │      LvI 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-39832 
                        │      │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5006 
                        │      │                  ├ [6]: https://ubuntu.com/security/notices/USN-8447-1 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2026-39832 
                        │      ├ PublishedDate   : 2026-05-22T04:16:22.663Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:39.773Z 
                        ├ [10] ╭ VulnerabilityID : CVE-2026-39833 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5005 
                        │      ├ PkgID           : golang.org/x/crypto@v0.49.0 
                        │      ├ PkgName         : golang.org/x/crypto 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/golang.org/x/crypto@v0.49.0 
                        │      │                  ╰ UID : 7902b3f05806d8b5 
                        │      ├ InstalledVersion: v0.49.0 
                        │      ├ FixedVersion    : 0.52.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39833 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cc432c2fb4e870ee16dfcae9bc6cd2406c53ddbaeb1d262e8d608
                        │      │                   7f5304e970d 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39834 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:64e1f7664086ad65b6c715d9f6e46e83642751edc3b3493cd36c6
                        │      │                   0510affe9c4 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-46598 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:41e63ae337d691ac980129299053804038929a8174cd4d875478d
                        │      │                   ac023ea3475 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25680 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:685f23e453b6cab6daceadf408dfeca835162a6515a12949c9f49
                        │      │                   c1755508318 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-25681 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:4c54ce0a0229efe018c5848296dc8e0bfb429032a62383b888f07
                        │      │                   c39f4ba5ad3 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27136 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0a692e4a7a5a59155541991f1628c10457f28102fb6709e0b50ec
                        │      │                   8ecc6a922a6 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:759de97f14a1d18a69e592db486148948c1badeeb66bac8b4c4df
                        │      │                   fddb1437eb8 
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
                        │      │                  ├ [9] : https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [10]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [11]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [12]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ╰ [13]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39821 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c6186fa077fd6b15f9cbaa8eac7649da76a9c25e12018f16a161b
                        │      │                   a14a624a3dc 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42502 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c4bb68a3f2660f6d25cdcf230a1a3fe4fde03f912804d8733c61d
                        │      │                   cd33574d0b2 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42506 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:efe6b06f56551b233f8abbab5ca8e2493b650cd0efc284df986d5
                        │      │                   79aff964799 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39824 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:0bc9af6e4bb90a666d4589d123726b70357cbdea8d7c5267e2303
                        │      │                   43de0a8b7d5 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-27145 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c013085f643d1482c173f9839dd6e9737dde8c9134dd9170cfb66
                        │      │                   db969a47200 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33811 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:02f6f3b8e791d99eb23137f8155a9c374832d8645c7e090294532
                        │      │                   e3f9cec455c 
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
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-33814 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:631718cd7c3bf20409e3e546f304d50ec406333092cbd6582741b
                        │      │                   fa2ecff6773 
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
                        │      │                  ├ [9] : https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [10]: https://nvd.nist.gov/vuln/detail/CVE-2026-33814 
                        │      │                  ├ [11]: https://pkg.go.dev/vuln/GO-2026-4918 
                        │      │                  ├ [12]: https://ubuntu.com/security/notices/USN-8430-1 
                        │      │                  ╰ [13]: https://www.cve.org/CVERecord?id=CVE-2026-33814 
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
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39820 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:c97ccb7b6604356f30d2b5c09692fefad3c11922b785bfeb2f0e5
                        │      │                   f4eda298011 
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
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39820 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4986 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.187Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.193Z 
                        ├ [25] ╭ VulnerabilityID : CVE-2026-39823 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4982 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39823 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7a10b6626f576f2fdd5fc354937d73c184379dc2d22f39be4e642
                        │      │                   afa8d32048d 
                        │      ├ Title           : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly  ... 
                        │      ├ Description     : CVE-2026-27142 fixed a vulnerability in which URLs were not
                        │      │                   correctly escaped inside of a <meta> tag's <content>
                        │      │                   attribute. If the URL content were to insert ASCII
                        │      │                   whitespaces around the '=' rune inside of the <content>
                        │      │                   attribute, the escaper would fail to similarly escape it,
                        │      │                   leading to XSS. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://go.dev/cl/769920 
                        │      │                  ├ [1]: https://go.dev/issue/78913 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39823.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39823 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4982 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.29Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.473Z 
                        ├ [26] ╭ VulnerabilityID : CVE-2026-39825 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4976 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39825 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:7424027549b8bb275f4d7c6dfeedc3e525b1743ce807881c437e5
                        │      │                   5e3e247a841 
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
                        │      ├ Severity        : HIGH 
                        │      ├ VendorSeverity   ╭ amazon     : 3 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ╰ photon     : 2 
                        │      ├ CVSS             ─ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0]: https://go.dev/cl/770541 
                        │      │                  ├ [1]: https://go.dev/issue/78948 
                        │      │                  ├ [2]: https://groups.google.com/g/golang-announce/c/qcCIEXso
                        │      │                  │      47M 
                        │      │                  ├ [3]: https://linux.oracle.com/cve/CVE-2026-39825.html 
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39825 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4976 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.39Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:38.77Z 
                        ├ [27] ╭ VulnerabilityID : CVE-2026-39836 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4971 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ SeveritySource  : nvd 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39836 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:82da16418429072a30486d35317f59f1c8cb8c53f106373c68122
                        │      │                   2238083e622 
                        │      ├ Title           : ELSA-2026-22112:  go-toolset:ol8 security update (IMPORTANT) 
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
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-39836 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4971 
                        │      ├ PublishedDate   : 2026-05-07T20:16:43.593Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:42:40.34Z 
                        ├ [28] ╭ VulnerabilityID : CVE-2026-42499 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4977 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42499 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:cf509e94d4aadd86ef747cd9290bba339a05a32807c32131067b3
                        │      │                   6af9fca6226 
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
                        │      │                  ├ [4]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2026-42499 
                        │      │                  ╰ [6]: https://pkg.go.dev/vuln/GO-2026-4977 
                        │      ├ PublishedDate   : 2026-05-07T20:16:44.54Z 
                        │      ╰ LastModifiedDate: 2026-06-17T10:47:56.183Z 
                        ├ [29] ╭ VulnerabilityID : CVE-2026-42504 
                        │      ├ VendorIDs        ─ [0]: GO-2026-5038 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.11, 1.26.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42504 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8c150b71040b6f25c650eb04299fd3aef4a0b3ebaccf2810cb855
                        │      │                   4bc3ca76f3b 
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
                        ├ [30] ╭ VulnerabilityID : CVE-2026-39826 
                        │      ├ VendorIDs        ─ [0]: GO-2026-4980 
                        │      ├ PkgID           : stdlib@v1.26.2 
                        │      ├ PkgName         : stdlib 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/stdlib@v1.26.2 
                        │      │                  ╰ UID : 83c42d84cdb2ccfe 
                        │      ├ InstalledVersion: v1.26.2 
                        │      ├ FixedVersion    : 1.25.10, 1.26.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                        │      │                  │         08e6f99dad39e14a2ece 
                        │      │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                        │      │                            791cc80e810a1d1c4bb6 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-39826 
                        │      ├ DataSource       ╭ ID  : govulndb 
                        │      │                  ├ Name: The Go Vulnerability Database 
                        │      │                  ╰ URL : https://pkg.go.dev/vuln/ 
                        │      ├ Fingerprint     : sha256:8162493545d36fe0961f5974e1b183ed8444915dac81b3d4c5256
                        │      │                   95fb986e58e 
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
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2026-22112.html 
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
                               ├ Layer            ╭ Digest: sha256:2f91fd0cc64b67bb4ee0e9ace7b18e8fbbed46d13ea1
                               │                  │         08e6f99dad39e14a2ece 
                               │                  ╰ DiffID: sha256:d53097bcb59c55aa0a821cfdad03fd2d3b100e46d12b
                               │                            791cc80e810a1d1c4bb6 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2026-42507 
                               ├ DataSource       ╭ ID  : govulndb 
                               │                  ├ Name: The Go Vulnerability Database 
                               │                  ╰ URL : https://pkg.go.dev/vuln/ 
                               ├ Fingerprint     : sha256:cfa8b47574116ee0d929680a01e879ac02620a1c6698bb2007624
                               │                   77acbbfff9d 
                               ├ Title           : net/textproto: golang: Golang net/textproto: Misleading
                               │                   error messages via input injection 
                               ├ Description     : When returning errors, functions in the net/textproto
                               │                   package would include its input as part of the error. This
                               │                   might allow an attacker to inject misleading content to
                               │                   errors that are printed or logged. 
                               ├ Severity        : MEDIUM 
                               ├ VendorSeverity   ╭ amazon : 3 
                               │                  ├ bitnami: 2 
                               │                  ╰ redhat : 2 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 5.3 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                               │                            │           L/A:N 
                               │                            ╰ V3Score : 5.3 
                               ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2026-42507 
                               │                  ├ [1]: https://go.dev/cl/777060 
                               │                  ├ [2]: https://go.dev/issue/79346 
                               │                  ├ [3]: https://groups.google.com/g/golang-announce/c/tKs3rmcB
                               │                  │      cKw 
                               │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2026-42507 
                               │                  ├ [5]: https://pkg.go.dev/vuln/GO-2026-5039 
                               │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2026-42507 
                               ├ PublishedDate   : 2026-06-02T23:16:38.027Z 
                               ╰ LastModifiedDate: 2026-06-17T10:47:57.137Z 
```

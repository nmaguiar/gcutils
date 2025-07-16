````yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.23.0_alpha20250612) 
│     ├ Class : os-pkgs 
│     ╰ Type  : alpine 
├ [1] ╭ Target         : Java 
│     ├ Class          : lang-pkgs 
│     ├ Type           : jar 
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : CVE-2025-48924 
│                             ├ PkgName         : org.apache.commons:commons-lang3 
│                             ├ PkgPath         : openaf/openaf.jar 
│                             ├ PkgIdentifier    ╭ PURL: pkg:maven/org.apache.commons/commons-lang3@3.17.0 
│                             │                  ╰ UID : 36abc6aa3ef9156f 
│                             ├ InstalledVersion: 3.17.0 
│                             ├ FixedVersion    : 3.18.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:641eb5e82ad8676eec0aa33ee618ca745df872b354ae4
│                             │                  │         9004bf8f118d145dcee 
│                             │                  ╰ DiffID: sha256:0b0f59fc74b2c5e82c5d16a0a2d1c6d8937a52ccf58dc
│                             │                            4f3b288accffe4a8dd3 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-48924 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Maven 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Amaven 
│                             ├ Title           : commons-lang/commons-lang: org.apache.commons/commons-lang3:
│                             │                   Uncontrolled Recursion vulnerability in Apache Commons Lang 
│                             ├ Description     : Uncontrolled Recursion vulnerability in Apache Commons Lang.
│                             │                   
│                             │                   This issue affects Apache Commons Lang: Starting with
│                             │                   commons-lang:commons-lang 2.0 to 2.6, and, from
│                             │                   org.apache.commons:commons-lang3 3.0 before 3.18.0.
│                             │                   The methods ClassUtils.getClass(...) can throw
│                             │                   StackOverflowError on very long inputs. Because an Error is
│                             │                   usually not handled by applications and libraries, a 
│                             │                   StackOverflowError could cause an application to stop.
│                             │                   Users are recommended to upgrade to version 3.18.0, which
│                             │                   fixes the issue. 
│                             ├ Severity        : MEDIUM 
│                             ├ CweIDs           ─ [0]: CWE-674 
│                             ├ VendorSeverity   ╭ ghsa  : 2 
│                             │                  ╰ redhat: 1 
│                             ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/
│                             │                  │        │           A:N 
│                             │                  │        ╰ V3Score : 6.5 
│                             │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/
│                             │                           │           A:L 
│                             │                           ╰ V3Score : 3.7 
│                             ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2025-48924 
│                             │                  ├ [1]: https://github.com/apache/commons-lang 
│                             │                  ├ [2]: https://github.com/apache/commons-lang/commit/b424803ab
│                             │                  │      db2bec818e4fbcb251ce031c22aca53 
│                             │                  ├ [3]: https://lists.apache.org/thread/bgv0lpswokgol11tloxnjfz
│                             │                  │      dl7yrc1g1 
│                             │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-48924 
│                             │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2025-48924 
│                             ├ PublishedDate   : 2025-07-11T15:15:24.347Z 
│                             ╰ LastModifiedDate: 2025-07-15T13:14:49.98Z 
├ [2] ╭ Target: Node.js 
│     ├ Class : lang-pkgs 
│     ╰ Type  : node-pkg 
├ [3] ╭ Target: Python 
│     ├ Class : lang-pkgs 
│     ╰ Type  : python-pkg 
├ [4] ╭ Target         : usr/bin/prometheus 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GHSA-fv92-fjc5-jj9h 
│                             ├ PkgID           : github.com/go-viper/mapstructure/v2@v2.2.1 
│                             ├ PkgName         : github.com/go-viper/mapstructure/v2 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/go-viper/mapstructure/v2@v2.2.1 
│                             │                  ╰ UID : e2c1d5fc4a675546 
│                             ├ InstalledVersion: v2.2.1 
│                             ├ FixedVersion    : 2.3.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:641eb5e82ad8676eec0aa33ee618ca745df872b354ae4
│                             │                  │         9004bf8f118d145dcee 
│                             │                  ╰ DiffID: sha256:0b0f59fc74b2c5e82c5d16a0a2d1c6d8937a52ccf58dc
│                             │                            4f3b288accffe4a8dd3 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-fv92-fjc5-jj9h 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : mapstructure May Leak Sensitive Information in Logs When
│                             │                   Processing Malformed Data 
│                             ├ Description     : ### Summary
│                             │                   
│                             │                   Use of this library in a security-critical context may result
│                             │                    in leaking sensitive information, if used to process
│                             │                   sensitive fields.
│                             │                   ### Details
│                             │                   OpenBao (and presumably HashiCorp Vault) have surfaced error
│                             │                   messages from `mapstructure` as follows:
│                             │                   https://github.com/openbao/openbao/blob/98c3a59c040efca724353
│                             │                   ca46ca79bd5cdbab920/sdk/framework/field_data.go#L43-L50
│                             │                   ```go
│                             │                   			_, _, err := d.getPrimitive(field, schema)
│                             │                   			if err != nil {
│                             │                   				return fmt.Errorf("error converting input for field %q:
│                             │                   %w", field, err)
│                             │                   			}
│                             │                   ```
│                             │                   where this calls `mapstructure.WeakDecode(...)`:
│                             │                   ca46ca79bd5cdbab920/sdk/framework/field_data.go#L181-L193
│                             │                   func (d *FieldData) getPrimitive(k string, schema
│                             │                   *FieldSchema) (interface{}, bool, error) {
│                             │                   	raw, ok := d.Raw[k]
│                             │                   	if !ok {
│                             │                   		return nil, false, nil
│                             │                   	}
│                             │                   	switch t := schema.Type; t {
│                             │                   	case TypeBool:
│                             │                   		var result bool
│                             │                   		if err := mapstructure.WeakDecode(raw, &result); err != nil
│                             │                    {
│                             │                   			return nil, false, err
│                             │                   		}
│                             │                   		return result, true, nil
│                             │                   Notably, `WeakDecode(...)` eventually calls one of the decode
│                             │                    helpers, which surfaces the original value:
│                             │                   https://github.com/go-viper/mapstructure/blob/1a66224d5e54d87
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L679-L686
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L726-L730
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L783-L787
│                             │                   & more.
│                             │                   ### PoC
│                             │                   To reproduce with OpenBao:
│                             │                   $ podman run -p 8300:8300 openbao/openbao:latest server -dev
│                             │                   -dev-root-token-id=root -dev-listen-address=0.0.0.0:8300
│                             │                   and in a new tab:
│                             │                   $ BAO_TOKEN=root BAO_ADDR=http://localhost:8300 bao auth
│                             │                   enable userpass
│                             │                   Success! Enabled userpass auth method at: userpass/
│                             │                   $ curl -X PUT -H "X-Vault-Request: true" -H "X-Vault-Token:
│                             │                   root" -d '{"password":{"asdf":"my-sensitive-value"}}'
│                             │                   "http://localhost:8300/v1/auth/userpass/users/adsf"
│                             │                   {"errors":["error converting input for field \"password\": ''
│                             │                    expected type 'string', got unconvertible type
│                             │                   'map[string]interface {}', value:
│                             │                   'map[asdf:my-sensitive-value]'"]}
│                             │                   ### Impact
│                             │                   This is an information disclosure bug with little mitigation.
│                             │                    See
│                             │                   https://discuss.hashicorp.com/t/hcsec-2025-09-vault-may-expos
│                             │                   e-sensitive-information-in-error-logs-when-processing-malform
│                             │                   ed-data-with-the-kv-v2-plugin/74717 for a previous version.
│                             │                   That version was fixed, but this is in the second part of
│                             │                   that error message (starting at `'' expected a map, got
│                             │                   'string'` -- when the field type is `string` and a `map` is
│                             │                   provided, we see the above information leak -- the previous
│                             │                   example had a `map` type field with a `string` value
│                             │                   provided).
│                             │                   This was rated 4.5 Medium by HashiCorp in the past iteration. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ─ ghsa: 2 
│                             ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N 
│                             │                         ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://github.com/go-viper/mapstructure 
│                             │                  ╰ [1]: https://github.com/go-viper/mapstructure/security/advis
│                             │                         ories/GHSA-fv92-fjc5-jj9h 
│                             ├ PublishedDate   : 2025-06-27T16:24:59Z 
│                             ╰ LastModifiedDate: 2025-06-27T16:24:59Z 
├ [5] ╭ Target         : usr/bin/promtool 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ─ [0] ╭ VulnerabilityID : GHSA-fv92-fjc5-jj9h 
│                             ├ PkgID           : github.com/go-viper/mapstructure/v2@v2.2.1 
│                             ├ PkgName         : github.com/go-viper/mapstructure/v2 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/go-viper/mapstructure/v2@v2.2.1 
│                             │                  ╰ UID : 83ec1cc3df41ba2 
│                             ├ InstalledVersion: v2.2.1 
│                             ├ FixedVersion    : 2.3.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:641eb5e82ad8676eec0aa33ee618ca745df872b354ae4
│                             │                  │         9004bf8f118d145dcee 
│                             │                  ╰ DiffID: sha256:0b0f59fc74b2c5e82c5d16a0a2d1c6d8937a52ccf58dc
│                             │                            4f3b288accffe4a8dd3 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-fv92-fjc5-jj9h 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : mapstructure May Leak Sensitive Information in Logs When
│                             │                   Processing Malformed Data 
│                             ├ Description     : ### Summary
│                             │                   
│                             │                   Use of this library in a security-critical context may result
│                             │                    in leaking sensitive information, if used to process
│                             │                   sensitive fields.
│                             │                   ### Details
│                             │                   OpenBao (and presumably HashiCorp Vault) have surfaced error
│                             │                   messages from `mapstructure` as follows:
│                             │                   https://github.com/openbao/openbao/blob/98c3a59c040efca724353
│                             │                   ca46ca79bd5cdbab920/sdk/framework/field_data.go#L43-L50
│                             │                   ```go
│                             │                   			_, _, err := d.getPrimitive(field, schema)
│                             │                   			if err != nil {
│                             │                   				return fmt.Errorf("error converting input for field %q:
│                             │                   %w", field, err)
│                             │                   			}
│                             │                   ```
│                             │                   where this calls `mapstructure.WeakDecode(...)`:
│                             │                   ca46ca79bd5cdbab920/sdk/framework/field_data.go#L181-L193
│                             │                   func (d *FieldData) getPrimitive(k string, schema
│                             │                   *FieldSchema) (interface{}, bool, error) {
│                             │                   	raw, ok := d.Raw[k]
│                             │                   	if !ok {
│                             │                   		return nil, false, nil
│                             │                   	}
│                             │                   	switch t := schema.Type; t {
│                             │                   	case TypeBool:
│                             │                   		var result bool
│                             │                   		if err := mapstructure.WeakDecode(raw, &result); err != nil
│                             │                    {
│                             │                   			return nil, false, err
│                             │                   		}
│                             │                   		return result, true, nil
│                             │                   Notably, `WeakDecode(...)` eventually calls one of the decode
│                             │                    helpers, which surfaces the original value:
│                             │                   https://github.com/go-viper/mapstructure/blob/1a66224d5e54d87
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L679-L686
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L726-L730
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L783-L787
│                             │                   & more.
│                             │                   ### PoC
│                             │                   To reproduce with OpenBao:
│                             │                   $ podman run -p 8300:8300 openbao/openbao:latest server -dev
│                             │                   -dev-root-token-id=root -dev-listen-address=0.0.0.0:8300
│                             │                   and in a new tab:
│                             │                   $ BAO_TOKEN=root BAO_ADDR=http://localhost:8300 bao auth
│                             │                   enable userpass
│                             │                   Success! Enabled userpass auth method at: userpass/
│                             │                   $ curl -X PUT -H "X-Vault-Request: true" -H "X-Vault-Token:
│                             │                   root" -d '{"password":{"asdf":"my-sensitive-value"}}'
│                             │                   "http://localhost:8300/v1/auth/userpass/users/adsf"
│                             │                   {"errors":["error converting input for field \"password\": ''
│                             │                    expected type 'string', got unconvertible type
│                             │                   'map[string]interface {}', value:
│                             │                   'map[asdf:my-sensitive-value]'"]}
│                             │                   ### Impact
│                             │                   This is an information disclosure bug with little mitigation.
│                             │                    See
│                             │                   https://discuss.hashicorp.com/t/hcsec-2025-09-vault-may-expos
│                             │                   e-sensitive-information-in-error-logs-when-processing-malform
│                             │                   ed-data-with-the-kv-v2-plugin/74717 for a previous version.
│                             │                   That version was fixed, but this is in the second part of
│                             │                   that error message (starting at `'' expected a map, got
│                             │                   'string'` -- when the field type is `string` and a `map` is
│                             │                   provided, we see the above information leak -- the previous
│                             │                   example had a `map` type field with a `string` value
│                             │                   provided).
│                             │                   This was rated 4.5 Medium by HashiCorp in the past iteration. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ─ ghsa: 2 
│                             ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N 
│                             │                         ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://github.com/go-viper/mapstructure 
│                             │                  ╰ [1]: https://github.com/go-viper/mapstructure/security/advis
│                             │                         ories/GHSA-fv92-fjc5-jj9h 
│                             ├ PublishedDate   : 2025-06-27T16:24:59Z 
│                             ╰ LastModifiedDate: 2025-06-27T16:24:59Z 
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
│                       │     ├ Layer            ╭ Digest: sha256:641eb5e82ad8676eec0aa33ee618ca745df872b354ae4
│                       │     │                  │         9004bf8f118d145dcee 
│                       │     │                  ╰ DiffID: sha256:0b0f59fc74b2c5e82c5d16a0a2d1c6d8937a52ccf58dc
│                       │     │                            4f3b288accffe4a8dd3 
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
│                       ╰ [1] ╭ VulnerabilityID : GHSA-fv92-fjc5-jj9h 
│                             ├ PkgID           : github.com/go-viper/mapstructure/v2@v2.2.1 
│                             ├ PkgName         : github.com/go-viper/mapstructure/v2 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/go-viper/mapstructure/v2@v2.2.1 
│                             │                  ╰ UID : 31212e5e6437563 
│                             ├ InstalledVersion: v2.2.1 
│                             ├ FixedVersion    : 2.3.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:641eb5e82ad8676eec0aa33ee618ca745df872b354ae4
│                             │                  │         9004bf8f118d145dcee 
│                             │                  ╰ DiffID: sha256:0b0f59fc74b2c5e82c5d16a0a2d1c6d8937a52ccf58dc
│                             │                            4f3b288accffe4a8dd3 
│                             ├ SeveritySource  : ghsa 
│                             ├ PrimaryURL      : https://github.com/advisories/GHSA-fv92-fjc5-jj9h 
│                             ├ DataSource       ╭ ID  : ghsa 
│                             │                  ├ Name: GitHub Security Advisory Go 
│                             │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                             │                          osystem%3Ago 
│                             ├ Title           : mapstructure May Leak Sensitive Information in Logs When
│                             │                   Processing Malformed Data 
│                             ├ Description     : ### Summary
│                             │                   
│                             │                   Use of this library in a security-critical context may result
│                             │                    in leaking sensitive information, if used to process
│                             │                   sensitive fields.
│                             │                   ### Details
│                             │                   OpenBao (and presumably HashiCorp Vault) have surfaced error
│                             │                   messages from `mapstructure` as follows:
│                             │                   https://github.com/openbao/openbao/blob/98c3a59c040efca724353
│                             │                   ca46ca79bd5cdbab920/sdk/framework/field_data.go#L43-L50
│                             │                   ```go
│                             │                   			_, _, err := d.getPrimitive(field, schema)
│                             │                   			if err != nil {
│                             │                   				return fmt.Errorf("error converting input for field %q:
│                             │                   %w", field, err)
│                             │                   			}
│                             │                   ```
│                             │                   where this calls `mapstructure.WeakDecode(...)`:
│                             │                   ca46ca79bd5cdbab920/sdk/framework/field_data.go#L181-L193
│                             │                   func (d *FieldData) getPrimitive(k string, schema
│                             │                   *FieldSchema) (interface{}, bool, error) {
│                             │                   	raw, ok := d.Raw[k]
│                             │                   	if !ok {
│                             │                   		return nil, false, nil
│                             │                   	}
│                             │                   	switch t := schema.Type; t {
│                             │                   	case TypeBool:
│                             │                   		var result bool
│                             │                   		if err := mapstructure.WeakDecode(raw, &result); err != nil
│                             │                    {
│                             │                   			return nil, false, err
│                             │                   		}
│                             │                   		return result, true, nil
│                             │                   Notably, `WeakDecode(...)` eventually calls one of the decode
│                             │                    helpers, which surfaces the original value:
│                             │                   https://github.com/go-viper/mapstructure/blob/1a66224d5e54d87
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L679-L686
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L726-L730
│                             │                   57f63bd66339cf764c3292c21/mapstructure.go#L783-L787
│                             │                   & more.
│                             │                   ### PoC
│                             │                   To reproduce with OpenBao:
│                             │                   $ podman run -p 8300:8300 openbao/openbao:latest server -dev
│                             │                   -dev-root-token-id=root -dev-listen-address=0.0.0.0:8300
│                             │                   and in a new tab:
│                             │                   $ BAO_TOKEN=root BAO_ADDR=http://localhost:8300 bao auth
│                             │                   enable userpass
│                             │                   Success! Enabled userpass auth method at: userpass/
│                             │                   $ curl -X PUT -H "X-Vault-Request: true" -H "X-Vault-Token:
│                             │                   root" -d '{"password":{"asdf":"my-sensitive-value"}}'
│                             │                   "http://localhost:8300/v1/auth/userpass/users/adsf"
│                             │                   {"errors":["error converting input for field \"password\": ''
│                             │                    expected type 'string', got unconvertible type
│                             │                   'map[string]interface {}', value:
│                             │                   'map[asdf:my-sensitive-value]'"]}
│                             │                   ### Impact
│                             │                   This is an information disclosure bug with little mitigation.
│                             │                    See
│                             │                   https://discuss.hashicorp.com/t/hcsec-2025-09-vault-may-expos
│                             │                   e-sensitive-information-in-error-logs-when-processing-malform
│                             │                   ed-data-with-the-kv-v2-plugin/74717 for a previous version.
│                             │                   That version was fixed, but this is in the second part of
│                             │                   that error message (starting at `'' expected a map, got
│                             │                   'string'` -- when the field type is `string` and a `map` is
│                             │                   provided, we see the above information leak -- the previous
│                             │                   example had a `map` type field with a `string` value
│                             │                   provided).
│                             │                   This was rated 4.5 Medium by HashiCorp in the past iteration. 
│                             ├ Severity        : MEDIUM 
│                             ├ VendorSeverity   ─ ghsa: 2 
│                             ├ CVSS             ─ ghsa ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N 
│                             │                         ╰ V3Score : 5.3 
│                             ├ References       ╭ [0]: https://github.com/go-viper/mapstructure 
│                             │                  ╰ [1]: https://github.com/go-viper/mapstructure/security/advis
│                             │                         ories/GHSA-fv92-fjc5-jj9h 
│                             ├ PublishedDate   : 2025-06-27T16:24:59Z 
│                             ╰ LastModifiedDate: 2025-06-27T16:24:59Z 
├ [7] ╭ Target: usr/share/grafana/bin/grafana-cli 
│     ├ Class : lang-pkgs 
│     ╰ Type  : gobinary 
╰ [8] ╭ Target: usr/share/grafana/bin/grafana-server 
      ├ Class : lang-pkgs 
      ╰ Type  : gobinary 
````

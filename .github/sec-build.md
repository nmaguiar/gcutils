````yaml
╭ [0] ╭ Target: nmaguiar/gcutils:build (alpine 3.23.0_alpha20250612) 
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
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-54388 
│                       │     ├ PkgID           : github.com/docker/docker@v28.2.2+incompatible 
│                       │     ├ PkgName         : github.com/docker/docker 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v28.2.2%2Bincompat
│                       │     │                  │       ible 
│                       │     │                  ╰ UID : a7f6f4efaa24e38e 
│                       │     ├ InstalledVersion: v28.2.2+incompatible 
│                       │     ├ FixedVersion    : 28.3.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53dddf
│                       │     │                  │         0cd2bf50b021cbc8562 
│                       │     │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040da
│                       │     │                            26c555f5f835bf9a62c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-54388 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : Moby firewalld reload makes published container ports
│                       │     │                   accessible from remote hosts  
│                       │     ├ Description     : Moby is an open source container framework developed by
│                       │     │                   Docker Inc. that is distributed as Docker Engine, Mirantis
│                       │     │                   Container Runtime, and various other downstream
│                       │     │                   projects/products. In versions 28.2.0 through 28.3.2, when
│                       │     │                   the firewalld service is reloaded it removes all iptables
│                       │     │                   rules including those created by Docker. While Docker should
│                       │     │                   automatically recreate these rules, versions before 28.3.3
│                       │     │                   fail to recreate the specific rules that block external
│                       │     │                   access to containers. This means that after a firewalld
│                       │     │                   reload, containers with ports published to localhost (like
│                       │     │                   127.0.0.1:8080) become accessible from remote machines that
│                       │     │                   have network routing to the Docker bridge, even though they
│                       │     │                   should only be accessible from the host itself. The
│                       │     │                   vulnerability only affects explicitly published ports -
│                       │     │                   unpublished ports remain protected. This issue is fixed in
│                       │     │                   version 28.3.3. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-909 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ References       ╭ [0]: https://github.com/moby/moby 
│                       │     │                  ├ [1]: https://github.com/moby/moby/commit/bea959c7b793b32a893
│                       │     │                  │      820b97c4eadc7c87fabb0 
│                       │     │                  ├ [2]: https://github.com/moby/moby/pull/50506 
│                       │     │                  ├ [3]: https://github.com/moby/moby/security/advisories/GHSA-x
│                       │     │                  │      4rx-4gw3-53p4 
│                       │     │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-54388 
│                       │     ├ PublishedDate   : 2025-07-30T14:15:28.693Z 
│                       │     ╰ LastModifiedDate: 2025-07-30T14:15:28.693Z 
│                       ╰ [1] ╭ VulnerabilityID : GHSA-fv92-fjc5-jj9h 
│                             ├ PkgID           : github.com/go-viper/mapstructure/v2@v2.2.1 
│                             ├ PkgName         : github.com/go-viper/mapstructure/v2 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/go-viper/mapstructure/v2@v2.2.1 
│                             │                  ╰ UID : e2c1d5fc4a675546 
│                             ├ InstalledVersion: v2.2.1 
│                             ├ FixedVersion    : 2.3.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53dddf
│                             │                  │         0cd2bf50b021cbc8562 
│                             │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040da
│                             │                            26c555f5f835bf9a62c 
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
│     ╰ Vulnerabilities ╭ [0] ╭ VulnerabilityID : CVE-2025-54388 
│                       │     ├ PkgID           : github.com/docker/docker@v28.2.2+incompatible 
│                       │     ├ PkgName         : github.com/docker/docker 
│                       │     ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/docker/docker@v28.2.2%2Bincompat
│                       │     │                  │       ible 
│                       │     │                  ╰ UID : a5222116e4820de6 
│                       │     ├ InstalledVersion: v28.2.2+incompatible 
│                       │     ├ FixedVersion    : 28.3.3 
│                       │     ├ Status          : fixed 
│                       │     ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53dddf
│                       │     │                  │         0cd2bf50b021cbc8562 
│                       │     │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040da
│                       │     │                            26c555f5f835bf9a62c 
│                       │     ├ SeveritySource  : ghsa 
│                       │     ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-54388 
│                       │     ├ DataSource       ╭ ID  : ghsa 
│                       │     │                  ├ Name: GitHub Security Advisory Go 
│                       │     │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+ec
│                       │     │                          osystem%3Ago 
│                       │     ├ Title           : Moby firewalld reload makes published container ports
│                       │     │                   accessible from remote hosts  
│                       │     ├ Description     : Moby is an open source container framework developed by
│                       │     │                   Docker Inc. that is distributed as Docker Engine, Mirantis
│                       │     │                   Container Runtime, and various other downstream
│                       │     │                   projects/products. In versions 28.2.0 through 28.3.2, when
│                       │     │                   the firewalld service is reloaded it removes all iptables
│                       │     │                   rules including those created by Docker. While Docker should
│                       │     │                   automatically recreate these rules, versions before 28.3.3
│                       │     │                   fail to recreate the specific rules that block external
│                       │     │                   access to containers. This means that after a firewalld
│                       │     │                   reload, containers with ports published to localhost (like
│                       │     │                   127.0.0.1:8080) become accessible from remote machines that
│                       │     │                   have network routing to the Docker bridge, even though they
│                       │     │                   should only be accessible from the host itself. The
│                       │     │                   vulnerability only affects explicitly published ports -
│                       │     │                   unpublished ports remain protected. This issue is fixed in
│                       │     │                   version 28.3.3. 
│                       │     ├ Severity        : MEDIUM 
│                       │     ├ CweIDs           ─ [0]: CWE-909 
│                       │     ├ VendorSeverity   ─ ghsa: 2 
│                       │     ├ References       ╭ [0]: https://github.com/moby/moby 
│                       │     │                  ├ [1]: https://github.com/moby/moby/commit/bea959c7b793b32a893
│                       │     │                  │      820b97c4eadc7c87fabb0 
│                       │     │                  ├ [2]: https://github.com/moby/moby/pull/50506 
│                       │     │                  ├ [3]: https://github.com/moby/moby/security/advisories/GHSA-x
│                       │     │                  │      4rx-4gw3-53p4 
│                       │     │                  ╰ [4]: https://nvd.nist.gov/vuln/detail/CVE-2025-54388 
│                       │     ├ PublishedDate   : 2025-07-30T14:15:28.693Z 
│                       │     ╰ LastModifiedDate: 2025-07-30T14:15:28.693Z 
│                       ╰ [1] ╭ VulnerabilityID : GHSA-fv92-fjc5-jj9h 
│                             ├ PkgID           : github.com/go-viper/mapstructure/v2@v2.2.1 
│                             ├ PkgName         : github.com/go-viper/mapstructure/v2 
│                             ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/go-viper/mapstructure/v2@v2.2.1 
│                             │                  ╰ UID : 83ec1cc3df41ba2 
│                             ├ InstalledVersion: v2.2.1 
│                             ├ FixedVersion    : 2.3.0 
│                             ├ Status          : fixed 
│                             ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53dddf
│                             │                  │         0cd2bf50b021cbc8562 
│                             │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040da
│                             │                            26c555f5f835bf9a62c 
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
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2018-15727 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 4.6.4, 5.2.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-15727 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: authentication bypass  knowing only a username of
│                       │      │                   an LDAP or OAuth user 
│                       │      ├ Description     : Grafana 2.x, 3.x, and 4.x before 4.6.4 and 5.x before 5.2.3
│                       │      │                   allows authentication bypass because an attacker can
│                       │      │                   generate a valid "remember me" cookie knowing only a
│                       │      │                   username of an LDAP or OAuth user. 
│                       │      ├ Severity        : CRITICAL 
│                       │      ├ CweIDs           ─ [0]: CWE-287 
│                       │      ├ VendorSeverity   ╭ ghsa  : 4 
│                       │      │                  ├ nvd   : 4 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 1 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:N/C:P/I:P/A:P 
│                       │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ├ V2Score : 7.5 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5.5 
│                       │      ├ References       ╭ [0] : http://www.securityfocus.com/bid/105184 
│                       │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2018:3829 
│                       │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2019:0019 
│                       │      │                  ├ [3] : https://access.redhat.com/security/cve/CVE-2018-15727 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/7baecf0d0de
│                       │      │                  │       ae0d865e45cf03e082bc0db3f28c3 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/commit/df83bf10a22
│                       │      │                  │       5811927644bdf6265fa80bdea9137 
│                       │      │                  ├ [6] : https://grafana.com/blog/2018/08/29/grafana-5.2.3-and
│                       │      │                  │       -4.6.4-released-with-important-security-fix 
│                       │      │                  ├ [7] : https://grafana.com/blog/2018/08/29/grafana-5.2.3-and
│                       │      │                  │       -4.6.4-released-with-important-security-fix/ 
│                       │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2018-15727 
│                       │      │                  ├ [9] : https://www.cve.org/CVERecord?id=CVE-2018-15727 
│                       │      │                  ╰ [10]: https://www.securityfocus.com/bid/105184 
│                       │      ├ PublishedDate   : 2018-08-29T15:29:00.24Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:51:20.95Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2023-3128 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.4.13, 9.3.16, 9.2.20, 8.5.27 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-3128 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: account takeover possible when using Azure AD OAuth 
│                       │      ├ Description     : Grafana is validating Azure AD accounts based on the email
│                       │      │                   claim. 
│                       │      │                   
│                       │      │                   On Azure AD, the profile email field is not unique and can
│                       │      │                   be easily modified. 
│                       │      │                   This leads to account takeover and authentication bypass
│                       │      │                   when Azure AD OAuth is configured with a multi-tenant app. 
│                       │      ├ Severity        : CRITICAL 
│                       │      ├ CweIDs           ─ [0]: CWE-290 
│                       │      ├ VendorSeverity   ╭ alma       : 4 
│                       │      │                  ├ bitnami    : 4 
│                       │      │                  ├ ghsa       : 4 
│                       │      │                  ├ nvd        : 4 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ rocky      : 4 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 9.8 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:L 
│                       │      │                  │         ╰ V3Score : 9.4 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           H/A:H 
│                       │      │                            ╰ V3Score : 9.8 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:4030 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2023-3128 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2213626 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2213626 
│                       │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       23-3128 
│                       │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2023-4030.html 
│                       │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2023:4030 
│                       │      │                  ├ [7] : https://github.com/grafana/bugbounty/security/advisor
│                       │      │                  │       ies/GHSA-gxh2-6vvc-rrgp 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/blob/69fc4e6bc0be2
│                       │      │                  │       a82085ab3885c2262a4d49e97d8/CHANGELOG.md 
│                       │      │                  ├ [10]: https://grafana.com/blog/2023/06/22/grafana-security-
│                       │      │                  │       release-for-cve-2023-3128/ 
│                       │      │                  ├ [11]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2023-3128 
│                       │      │                  ├ [12]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2023-3128/ 
│                       │      │                  ├ [13]: https://linux.oracle.com/cve/CVE-2023-3128.html 
│                       │      │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2023-6972.html 
│                       │      │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2023-3128 
│                       │      │                  ├ [16]: https://security.netapp.com/advisory/ntap-20230714-0004 
│                       │      │                  ├ [17]: https://security.netapp.com/advisory/ntap-20230714-00
│                       │      │                  │       04/ 
│                       │      │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2023-3128 
│                       │      ├ PublishedDate   : 2023-06-22T21:15:09.573Z 
│                       │      ╰ LastModifiedDate: 2025-02-13T17:16:55.49Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2020-12458 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.2.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-12458 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: information disclosure through world-readable
│                       │      │                   /var/lib/grafana/grafana.db 
│                       │      ├ Description     : An information-disclosure flaw was found in Grafana through
│                       │      │                   6.7.3. The database directory /var/lib/grafana and database
│                       │      │                   file /var/lib/grafana/grafana.db are world readable. This
│                       │      │                   can result in exposure of sensitive information (e.g.,
│                       │      │                   cleartext or encrypted datasource passwords). 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-732 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.5 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:L/AC:L/Au:N/C:P/I:N/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ├ V2Score : 2.1 
│                       │      │                  │         ╰ V3Score : 5.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 6.2 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-12458 
│                       │      │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=1827765 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/102448040d5
│                       │      │                  │       132460e3b0013e03ebedec0677e00 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/issues/8283 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-12458.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/CTQCKJZZY
│                       │      │                  │       XMCSHJFZZ3YXEO5NUBANGZS/ 
│                       │      │                  ├ [8] : https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/WEBCIEVSY
│                       │      │                  │       IDDCA7FTRS2IFUOYLIQU34A/ 
│                       │      │                  ├ [9] : https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/CTQCKJZZYXM
│                       │      │                  │       CSHJFZZ3YXEO5NUBANGZS 
│                       │      │                  ├ [10]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/WEBCIEVSYID
│                       │      │                  │       DCA7FTRS2IFUOYLIQU34A 
│                       │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2020-12458 
│                       │      │                  ├ [12]: https://security.netapp.com/advisory/ntap-20200518-0001 
│                       │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-20200518-00
│                       │      │                  │       01/ 
│                       │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2020-12458 
│                       │      ├ PublishedDate   : 2020-04-29T16:15:11.76Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:59:44.517Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2021-39226 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.5.11, 8.1.6 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2021-39226 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Snapshot authentication bypass 
│                       │      ├ Description     : Grafana is an open source data visualization platform. In
│                       │      │                   affected versions unauthenticated and authenticated users
│                       │      │                   are able to view the snapshot with the lowest database key
│                       │      │                   by accessing the literal paths: /dashboard/snapshot/:key, or
│                       │      │                    /api/snapshots/:key. If the snapshot "public_mode"
│                       │      │                   configuration setting is set to true (vs default of false),
│                       │      │                   unauthenticated users are able to delete the snapshot with
│                       │      │                   the lowest database key by accessing the literal path:
│                       │      │                   /api/snapshots-delete/:deleteKey. Regardless of the snapshot
│                       │      │                    "public_mode" setting, authenticated users are able to
│                       │      │                   delete the snapshot with the lowest database key by
│                       │      │                   accessing the literal paths: /api/snapshots/:key, or
│                       │      │                   /api/snapshots-delete/:deleteKey. The combination of
│                       │      │                   deletion and viewing enables a complete walk through all
│                       │      │                   snapshot data while resulting in complete snapshot data
│                       │      │                   loss. This issue has been resolved in versions 8.1.6 and
│                       │      │                   7.5.11. If for some reason you cannot upgrade you can use a
│                       │      │                   reverse proxy or similar to block access to the literal
│                       │      │                   paths: /api/snapshots/:key,
│                       │      │                   /api/snapshots-delete/:deleteKey, /dashboard/snapshot/:key,
│                       │      │                   and /api/snapshots/:key. They have no normal function and
│                       │      │                   can be disabled without side effects. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-287 
│                       │      │                  ╰ [1]: CWE-862 
│                       │      ├ VendorSeverity   ╭ bitnami    : 3 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ╰ rocky      : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.3 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:P/I:P/A:P 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ├ V2Score : 6.8 
│                       │      │                  │         ╰ V3Score : 7.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                            │           L/A:L 
│                       │      │                            ╰ V3Score : 7.3 
│                       │      ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2021/10/05/4 
│                       │      │                  ├ [1] : https://access.redhat.com/hydra/rest/securitydata/cve
│                       │      │                  │       /CVE-2021-39226.json 
│                       │      │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2021-39226 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/2d456a63758
│                       │      │                  │       55364d098ede379438bf7f0667269 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-69j6-29vr-p3j9 
│                       │      │                  ├ [6] : https://grafana.com/blog/2021/10/05/grafana-7.5.11-an
│                       │      │                  │       d-8.1.6-released-with-critical-security-fix/ 
│                       │      │                  ├ [7] : https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-7-5-11 
│                       │      │                  ├ [8] : https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-7-5-11/ 
│                       │      │                  ├ [9] : https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-8-1-6 
│                       │      │                  ├ [10]: https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-8-1-6/ 
│                       │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2021-39226.html 
│                       │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2021-3771.html 
│                       │      │                  ├ [13]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/DCKBFUSY6
│                       │      │                  │       V4VU5AQUYWKISREZX5NLQJT 
│                       │      │                  ├ [14]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/DCKBFUSY6
│                       │      │                  │       V4VU5AQUYWKISREZX5NLQJT/ 
│                       │      │                  ├ [15]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/E6ANHRDBX
│                       │      │                  │       QT6TURLP2THM26ZPDINFBEG 
│                       │      │                  ├ [16]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/E6ANHRDBX
│                       │      │                  │       QT6TURLP2THM26ZPDINFBEG/ 
│                       │      │                  ├ [17]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/DCKBFUSY6V4
│                       │      │                  │       VU5AQUYWKISREZX5NLQJT 
│                       │      │                  ├ [18]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/E6ANHRDBXQT
│                       │      │                  │       6TURLP2THM26ZPDINFBEG 
│                       │      │                  ├ [19]: https://nvd.nist.gov/vuln/detail/CVE-2021-39226 
│                       │      │                  ├ [20]: https://security.netapp.com/advisory/ntap-20211029-0008 
│                       │      │                  ├ [21]: https://security.netapp.com/advisory/ntap-20211029-00
│                       │      │                  │       08/ 
│                       │      │                  ├ [22]: https://www.cisa.gov/known-exploited-vulnerabilities-
│                       │      │                  │       catalog 
│                       │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2021-39226 
│                       │      ├ PublishedDate   : 2021-10-05T18:15:07.947Z 
│                       │      ╰ LastModifiedDate: 2025-02-18T14:53:42.247Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2022-35957 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.1.6, 9.0.9, 8.5.13 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-35957 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Escalation from admin to server admin when auth
│                       │      │                   proxy is used 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. Versions prior to 9.1.6 and 8.5.13 are
│                       │      │                   vulnerable to an escalation from admin to server admin when
│                       │      │                   auth proxy is used, allowing an admin to take over the
│                       │      │                   server admin account and gain full control of the grafana
│                       │      │                   instance. All installations should be upgraded as soon as
│                       │      │                   possible. As a workaround deactivate auth proxy following
│                       │      │                   the instructions at:
│                       │      │                   https://grafana.com/docs/grafana/latest/setup-grafana/config
│                       │      │                   ure-security/configure-authentication/auth-proxy/ 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-290 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 6.6 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 6.6 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 6.6 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                            │           H/A:H 
│                       │      │                            ╰ V3Score : 6.6 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:2167 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-35957 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2124669 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2125514 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131149 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2132868 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2132872 
│                       │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2023-2167.html 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-ff5c-938w-8c9q 
│                       │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2022-35957.html 
│                       │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2023-2167.html 
│                       │      │                  ├ [12]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/WYU5C2RIT
│                       │      │                  │       LHVZSTCWNGQWA6KSPYNXM2H/ 
│                       │      │                  ├ [13]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/WYU5C2RITLH
│                       │      │                  │       VZSTCWNGQWA6KSPYNXM2H 
│                       │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2022-35957 
│                       │      │                  ├ [15]: https://security.netapp.com/advisory/ntap-20221215-0001 
│                       │      │                  ├ [16]: https://security.netapp.com/advisory/ntap-20221215-00
│                       │      │                  │       01/ 
│                       │      │                  ╰ [17]: https://www.cve.org/CVERecord?id=CVE-2022-35957 
│                       │      ├ PublishedDate   : 2022-09-20T23:15:09.457Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:12:03.05Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2022-39307 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.2.4, 8.5.15 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39307 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: User enumeration via forget password 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. When using the forget password on the login
│                       │      │                   page, a POST request is made to the
│                       │      │                   `/api/user/password/sent-reset-email` URL. When the username
│                       │      │                    or email does not exist, a JSON response contains a “user
│                       │      │                   not found” message. This leaks information to
│                       │      │                   unauthenticated users and introduces a security risk. This
│                       │      │                   issue has been patched in 9.2.4 and backported to 8.5.15.
│                       │      │                   There are no known workarounds. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-200 
│                       │      │                  ╰ [1]: CWE-209 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
│                       │      │                  │         │           H/A:L 
│                       │      │                  │         ╰ V3Score : 6.7 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:6420 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39307 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2131146 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2131147 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131148 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2138014 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2138015 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2148252 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/2158420 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/2161274 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/2184483 
│                       │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2023-6420.html 
│                       │      │                  ├ [12]: https://github.com/grafana/grafana 
│                       │      │                  ├ [13]: https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-3p62-42x7-gxg5 
│                       │      │                  ├ [14]: https://grafana.com/blog/2022/11/08/security-release-
│                       │      │                  │       new-versions-of-grafana-with-critical-and-moderate-fi
│                       │      │                  │       xes-for-cve-2022-39328-cve-2022-39307-and-cve-2022-39
│                       │      │                  │       306/ 
│                       │      │                  ├ [15]: https://linux.oracle.com/cve/CVE-2022-39307.html 
│                       │      │                  ├ [16]: https://linux.oracle.com/errata/ELSA-2023-6420.html 
│                       │      │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2022-39307 
│                       │      │                  ├ [18]: https://security.netapp.com/advisory/ntap-20221215-0004 
│                       │      │                  ├ [19]: https://security.netapp.com/advisory/ntap-20221215-00
│                       │      │                  │       04/ 
│                       │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2022-39307 
│                       │      ├ PublishedDate   : 2022-11-09T23:15:12.617Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:18:00.08Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2023-2801 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.4.12, 9.5.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-2801 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: data source proxy race condition 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. 
│                       │      │                   
│                       │      │                   Using public dashboards users can query multiple distinct
│                       │      │                   data sources using mixed queries. However such query has a
│                       │      │                   possibility of crashing a Grafana instance.
│                       │      │                   The only feature that uses mixed queries at the moment is
│                       │      │                   public dashboards, but it's also possible to cause this by
│                       │      │                   calling the query API directly.
│                       │      │                   This might enable malicious users to crash Grafana instances
│                       │      │                    through that endpoint.
│                       │      │                   Users may upgrade to version 9.4.12 and 9.5.3 to receive a
│                       │      │                   fix. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-820 
│                       │      │                  ╰ [1]: CWE-662 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ├ nvd    : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-2801 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2801 
│                       │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2801/ 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2023-2801 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20230706-0002 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20230706-0002/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-2801 
│                       │      ├ PublishedDate   : 2023-06-06T19:15:11.413Z 
│                       │      ╰ LastModifiedDate: 2025-02-13T17:16:22.81Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2025-6023 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 1.9.2-0.20250521205822-0ba0b99665a9 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-6023 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Cross Site Scripting in Grafana 
│                       │      ├ Description     : An open redirect vulnerability has been identified in
│                       │      │                   Grafana OSS that can be exploited to achieve XSS attacks.
│                       │      │                   The vulnerability was introduced in Grafana v11.5.0.
│                       │      │                   
│                       │      │                   The open redirect can be chained with path traversal
│                       │      │                   vulnerabilities to achieve XSS.
│                       │      │                   Fixed in versions 12.0.2+security-01, 11.6.3+security-01,
│                       │      │                   11.5.6+security-01, 11.4.6+security-01 and 11.3.8+security-0
│                       │      │                   1 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-79 
│                       │      │                  ╰ [1]: CWE-601 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.6 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.6 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 7.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2025-6023 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/commit/0ba0b99665a
│                       │      │                  │       946cd96676ef85ec8bc83028cb1d7 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/40ed88fe86d
│                       │      │                  │       347bcde5ddaed6c4a20a95d2f0d55 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/5b00e21638f
│                       │      │                  │       565eed46acb4d0b7c009968df4c3b 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/commit/b6dd2b70c65
│                       │      │                  │       5c61b111b328f1a7dcca6b3954936 
│                       │      │                  ├ [6] : https://github.com/grafana/grafana/commit/e0ba4b48095
│                       │      │                  │       4f8a33aa2cff3229f6bcc05777bd9 
│                       │      │                  ├ [7] : https://grafana.com/blog/2025/07/17/grafana-security-
│                       │      │                  │       release-medium-and-high-severity-fixes-for-cve-2025-6
│                       │      │                  │       197-and-cve-2025-6023 
│                       │      │                  ├ [8] : https://grafana.com/blog/2025/07/17/grafana-security-
│                       │      │                  │       release-medium-and-high-severity-fixes-for-cve-2025-6
│                       │      │                  │       197-and-cve-2025-6023/ 
│                       │      │                  ├ [9] : https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2025-6023 
│                       │      │                  ├ [10]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2025-6023/ 
│                       │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2025-6023 
│                       │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2025-6023 
│                       │      ├ PublishedDate   : 2025-07-18T08:15:28.04Z 
│                       │      ╰ LastModifiedDate: 2025-07-22T13:06:27.983Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2018-1000816 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 5.3.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-1000816 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Cross site scripting in Influxdb and Graphite query
│                       │      │                    editor 
│                       │      ├ Description     : Grafana version confirmed for 5.2.4 and 5.3.0 contains a
│                       │      │                   Cross Site Scripting (XSS) vulnerability in Influxdb and
│                       │      │                   Graphite query editor that can result in Running arbitrary
│                       │      │                   js code in victims browser.. This attack appear to be
│                       │      │                   exploitable via Authenticated user must click on the input
│                       │      │                   field where the payload was previously inserted.. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 5.4 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:S/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 3.5 
│                       │      │                  │        ╰ V3Score : 5.4 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 5.4 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-1000816 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/commit/eabb04cec21d
│                       │      │                  │      c323347da1aab7fcbf2a6e9dd121 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/issues/13667 
│                       │      │                  ├ [4]: https://github.com/grafana/grafana/pull/13670 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2018-1000816 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2018-1000816 
│                       │      ├ PublishedDate   : 2018-12-20T15:29:00.643Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:40:25.107Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2018-12099 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 5.2.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-12099 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Cross-site Scripting (XSS) in dashboard links 
│                       │      ├ Description     : Grafana before 5.2.0-beta1 has XSS vulnerabilities in
│                       │      │                   dashboard links. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 1 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.8 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-12099 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/releases/tag/v5.2.0
│                       │      │                  │      -beta1 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2018-12099 
│                       │      │                  ├ [4]: https://security.netapp.com/advisory/ntap-20190416-0004 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20190416-0004/ 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2018-12099 
│                       │      ├ PublishedDate   : 2018-06-11T11:29:00.413Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:44:35.77Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2018-18623 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.0.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18623 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS vulnerability via the "Dashboard > Text Panel"
│                       │      │                   screen 
│                       │      ├ Description     : Grafana 5.3.1 has XSS via the "Dashboard > Text Panel"
│                       │      │                   screen. NOTE: this issue exists because of an incomplete fix
│                       │      │                    for CVE-2018-12099. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-18623 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana/issues/15293 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/issues/4117 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [4]: https://github.com/grafana/grafana/pull/14984 
│                       │      │                  ├ [5]: https://github.com/grafana/grafana/releases/tag/v6.0.0 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2018-18623 
│                       │      │                  ├ [7]: https://security.netapp.com/advisory/ntap-20200608-0008 
│                       │      │                  ├ [8]: https://security.netapp.com/advisory/ntap-20200608-0008/ 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2018-18623 
│                       │      ├ PublishedDate   : 2020-06-02T17:15:11.427Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:56:15.137Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2018-18624 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.0.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18624 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS vulnerability via a column style on the
│                       │      │                   "Dashboard > Table Panel" screen 
│                       │      ├ Description     : Grafana 5.3.1 has XSS via a column style on the "Dashboard >
│                       │      │                    Table Panel" screen. NOTE: this issue exists because of an
│                       │      │                   incomplete fix for CVE-2018-12099. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2018-18624 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/commit/0284747c88e
│                       │      │                  │       b9435899006d26ffaf65f89dec88e 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/pull/23816 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2018-18624.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2018-18624 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200608-0008 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200608-00
│                       │      │                  │       08/ 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2018-18624 
│                       │      ├ PublishedDate   : 2020-06-02T17:15:11.487Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:56:15.3Z 
│                       ├ [12] ╭ VulnerabilityID : CVE-2018-18625 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.0.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18625 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS vulnerability via a link on the "Dashboard >
│                       │      │                   All Panels > General" screen 
│                       │      ├ Description     : Grafana 5.3.1 has XSS via a link on the "Dashboard > All
│                       │      │                   Panels > General" screen. NOTE: this issue exists because of
│                       │      │                    an incomplete fix for CVE-2018-12099. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-18625 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/pull/14984 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/pull/22680#issuecom
│                       │      │                  │      ment-651195921 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2018-18625 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20200608-0008 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20200608-0008/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2018-18625 
│                       │      ├ PublishedDate   : 2020-06-02T17:15:11.567Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:56:15.443Z 
│                       ├ [13] ╭ VulnerabilityID : CVE-2019-13068 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.2.5 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-13068 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : Grafana Cross-site Scripting vulnerability 
│                       │      ├ Description     : public/app/features/panel/panel_ctrl.ts in Grafana before
│                       │      │                   6.2.5 allows HTML Injection in panel drilldown links (via
│                       │      │                   the Title or url field). 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa: 2 
│                       │      │                  ╰ nvd : 2 
│                       │      ├ CVSS             ╭ ghsa ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N 
│                       │      │                  │      ╰ V3Score : 5.4 
│                       │      │                  ╰ nvd  ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                         ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N 
│                       │      │                         ├ V2Score : 4.3 
│                       │      │                         ╰ V3Score : 5.4 
│                       │      ├ References       ╭ [0]: http://packetstormsecurity.com/files/171500/Grafana-6.
│                       │      │                  │      2.4-HTML-Injection.html 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/issues/17718 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/releases/tag/v6.2.5 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2019-13068 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20190710-0001 
│                       │      │                  ╰ [6]: https://security.netapp.com/advisory/ntap-20190710-0001/ 
│                       │      ├ PublishedDate   : 2019-06-30T00:15:11.313Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:24:08.057Z 
│                       ├ [14] ╭ VulnerabilityID : CVE-2019-19499 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.4.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-19499 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: arbitrary file read via MySQL data source 
│                       │      ├ Description     : Grafana <= 6.4.3 has an Arbitrary File Read vulnerability,
│                       │      │                   which could be exploited by an authenticated attacker that
│                       │      │                   has privileges to modify the data source configurations. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-89 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                  │        │           /A:N/E:P 
│                       │      │                  │        ╰ V3Score : 6.2 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:S/C:P/I:N/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4 
│                       │      │                  │        ╰ V3Score : 6.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2019-19499 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/blob/master/CHANGE
│                       │      │                  │       LOG.md#644-2019-11-06 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/19dbd27c5ca
│                       │      │                  │       a1a160bd5854b65a4e1fe2a8a4f00 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/pull/20192 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2019-19499.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2019-19499 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200918-0003 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200918-00
│                       │      │                  │       03/ 
│                       │      │                  ├ [10]: https://swarm.ptsecurity.com/grafana-6-4-3-arbitrary-
│                       │      │                  │       file-read/ 
│                       │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2019-19499 
│                       │      ├ PublishedDate   : 2020-08-28T15:15:11.953Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:34:50.603Z 
│                       ├ [15] ╭ VulnerabilityID : CVE-2020-11110 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.7.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-11110 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: stored XSS 
│                       │      ├ Description     : Grafana through 6.7.1 allows stored XSS due to insufficient
│                       │      │                   input protection in the originalUrl field, which allows an
│                       │      │                   attacker to inject JavaScript code that will be executed
│                       │      │                   after clicking on Open Original Dashboard after visiting the
│                       │      │                    snapshot. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 5.4 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 5.4 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:S/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 3.5 
│                       │      │                  │         ╰ V3Score : 5.4 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-11110 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/blob/master/CHANGE
│                       │      │                  │       LOG.md 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/fb114a75241
│                       │      │                  │       aaef4c08581b42509c750738b768a 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/pull/23254 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-11110.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2020-11110 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200810-0002 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200810-00
│                       │      │                  │       02/ 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2020-11110 
│                       │      ├ PublishedDate   : 2020-07-27T13:15:11.293Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:56:48.55Z 
│                       ├ [16] ╭ VulnerabilityID : CVE-2020-12245 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.7.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-12245 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS via column.title or cellLinkTooltip 
│                       │      ├ Description     : Grafana before 6.7.3 allows table-panel XSS via column.title
│                       │      │                    or cellLinkTooltip. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 4.3 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-06/msg00060.html 
│                       │      │                  ├ [1] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-07/msg00083.html 
│                       │      │                  ├ [2] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-10/msg00009.html 
│                       │      │                  ├ [3] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-10/msg00017.html 
│                       │      │                  ├ [4] : https://access.redhat.com/security/cve/CVE-2020-12245 
│                       │      │                  ├ [5] : https://community.grafana.com/t/release-notes-v6-7-x/
│                       │      │                  │       27119 
│                       │      │                  ├ [6] : https://github.com/grafana/grafana 
│                       │      │                  ├ [7] : https://github.com/grafana/grafana/blob/master/CHANGE
│                       │      │                  │       LOG.md#673-2020-04-23 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana/commit/0284747c88e
│                       │      │                  │       b9435899006d26ffaf65f89dec88e 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/pull/23816 
│                       │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2020-12245.html 
│                       │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2020-12245 
│                       │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-20200511-0001 
│                       │      │                  ├ [14]: https://security.netapp.com/advisory/ntap-20200511-00
│                       │      │                  │       01/ 
│                       │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2020-12245 
│                       │      ├ PublishedDate   : 2020-04-24T21:15:13.92Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:59:22.397Z 
│                       ├ [17] ╭ VulnerabilityID : CVE-2020-13430 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.0.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-13430 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS via the OpenTSDB datasource 
│                       │      ├ Description     : Grafana before 7.0.0 allows tag value XSS via the OpenTSDB
│                       │      │                   datasource. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 4.3 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-13430 
│                       │      │                  ├ [1] : https://github.com/advisories/GHSA-7m2x-qhrq-rp8h 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/pull/24539 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/releases/tag/v7.0.0 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-13430.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2020-13430 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200528-0003 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200528-00
│                       │      │                  │       03/ 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2020-13430 
│                       │      ├ PublishedDate   : 2020-05-24T18:15:10.097Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T05:01:14.78Z 
│                       ├ [18] ╭ VulnerabilityID : CVE-2020-24303 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.1.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-24303 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS via a query alias for the Elasticsearch and
│                       │      │                   Testdata datasource 
│                       │      ├ Description     : Grafana before 7.1.0-beta 1 allows XSS via a query alias for
│                       │      │                    the ElasticSearch datasource. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 4.3 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2020-24303 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/blob/master/CHANGEL
│                       │      │                  │      OG.md#710-beta-1-2020-07-01 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/pull/25401 
│                       │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2020-24303.html 
│                       │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2021-1859.html 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2020-24303 
│                       │      │                  ├ [7]: https://security.netapp.com/advisory/ntap-20201123-0002 
│                       │      │                  ├ [8]: https://security.netapp.com/advisory/ntap-20201123-0002/ 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2020-24303 
│                       │      ├ PublishedDate   : 2020-10-28T14:15:12.33Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T05:14:34.773Z 
│                       ├ [19] ╭ VulnerabilityID : CVE-2022-39229 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 8.5.14, 9.1.8 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39229 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: using email as a username can block other users
│                       │      │                   from signing in 
│                       │      ├ Description     : Grafana is an open source data visualization platform for
│                       │      │                   metrics, logs, and traces. Versions prior to 9.1.8 and
│                       │      │                   8.5.14 allow one user to block another user's login attempt
│                       │      │                   by registering someone else'e email address as a username. A
│                       │      │                    Grafana user’s username and email address are unique
│                       │      │                   fields, that means no other user can have the same username
│                       │      │                   or email address as another user. A user can have an email
│                       │      │                   address as a username. However, the login system allows
│                       │      │                   users to log in with either username or email address. Since
│                       │      │                    Grafana allows a user to log in with either their username
│                       │      │                   or email address, this creates an usual behavior where
│                       │      │                   `user_1` can register with one email address and `user_2`
│                       │      │                   can register their username as `user_1`’s email address.
│                       │      │                   This prevents `user_1` logging into the application since
│                       │      │                   `user_1`'s password won’t match with `user_2`'s email
│                       │      │                   address. Versions 9.1.8 and 8.5.14 contain a patch. There
│                       │      │                   are no workarounds for this issue. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-287 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 1 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:L 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:L 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:L 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:L 
│                       │      │                            ╰ V3Score : 4.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:2167 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39229 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2124669 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2125514 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131149 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2132868 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2132872 
│                       │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2023-2167.html 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/commit/5644758f0c5
│                       │      │                  │       ae9955a4e5480d71f9bef57fdce35 
│                       │      │                  ├ [10]: https://github.com/grafana/grafana/releases/tag/v9.1.8 
│                       │      │                  ├ [11]: https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-gj7m-853r-289r 
│                       │      │                  ├ [12]: https://linux.oracle.com/cve/CVE-2022-39229.html 
│                       │      │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2023-2784.html 
│                       │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2022-39229 
│                       │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2022-39229 
│                       │      ├ PublishedDate   : 2022-10-13T23:15:10.937Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:17:50.027Z 
│                       ├ [20] ╭ VulnerabilityID : CVE-2022-39324 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.2.8, 8.5.16 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39324 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Spoofing of the originalUrl parameter of snapshots 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. Prior to versions 8.5.16 and 9.2.8, malicious
│                       │      │                    user can create a snapshot and arbitrarily choose the
│                       │      │                   `originalUrl` parameter by editing the query, thanks to a
│                       │      │                   web proxy. When another user opens the URL of the snapshot,
│                       │      │                   they will be presented with the regular web interface
│                       │      │                   delivered by the trusted Grafana server. The `Open original
│                       │      │                   dashboard` button no longer points to the to the real
│                       │      │                   original dashboard but to the attacker’s injected URL. This
│                       │      │                   issue is fixed in versions 8.5.16 and 9.2.8. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 1 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 1 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 3.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
│                       │      │                  │         │           H/A:L 
│                       │      │                  │         ╰ V3Score : 6.7 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 3.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
│                       │      │                            │           H/A:L 
│                       │      │                            ╰ V3Score : 6.7 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:6420 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39324 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2131146 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2131147 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131148 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2138014 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2138015 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2148252 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/2158420 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/2161274 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/2184483 
│                       │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2023-6420.html 
│                       │      │                  ├ [12]: https://github.com/grafana/grafana 
│                       │      │                  ├ [13]: https://github.com/grafana/grafana/commit/239888f2298
│                       │      │                  │       3010576bb3a9135a7294e88c0c74a 
│                       │      │                  ├ [14]: https://github.com/grafana/grafana/commit/d7dcea71ea7
│                       │      │                  │       63780dc286792a0afd560bff2985c 
│                       │      │                  ├ [15]: https://github.com/grafana/grafana/pull/60232 
│                       │      │                  ├ [16]: https://github.com/grafana/grafana/pull/60256 
│                       │      │                  ├ [17]: https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-4724-7jwc-3fpw 
│                       │      │                  ├ [18]: https://grafana.com/blog/2023/01/25/grafana-security-
│                       │      │                  │       releases-new-versions-with-fixes-for-cve-2022-23552-c
│                       │      │                  │       ve-2022-41912-and-cve-2022-39324/ 
│                       │      │                  ├ [19]: https://linux.oracle.com/cve/CVE-2022-39324.html 
│                       │      │                  ├ [20]: https://linux.oracle.com/errata/ELSA-2023-6420.html 
│                       │      │                  ├ [21]: https://nvd.nist.gov/vuln/detail/CVE-2022-39324 
│                       │      │                  ├ [22]: https://security.netapp.com/advisory/ntap-20230309-00
│                       │      │                  │       10/ 
│                       │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2022-39324 
│                       │      ├ PublishedDate   : 2023-01-27T23:15:08.723Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:18:02.36Z 
│                       ├ [21] ╭ VulnerabilityID : CVE-2023-2183 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 8.5.26, 9.2.19, 9.3.15, 9.4.12, 9.5.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-2183 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: missing access control allows test alerts by
│                       │      │                   underprivileged user 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. 
│                       │      │                   
│                       │      │                   The option to send a test alert is not available from the
│                       │      │                   user panel UI for users having the Viewer role. It is still
│                       │      │                   possible for a user with the Viewer role to send a test
│                       │      │                   alert using the API as the API does not check access to this
│                       │      │                    function.
│                       │      │                   This might enable malicious users to abuse the functionality
│                       │      │                    by sending multiple alert messages to e-mail and Slack,
│                       │      │                   spamming users, prepare Phishing attack or block SMTP
│                       │      │                   server.
│                       │      │                   Users may upgrade to version 9.5.3, 9.4.12, 9.3.15, 9.2.19
│                       │      │                   and 8.5.26 to receive a fix. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ╭ [0]: CWE-284 
│                       │      │                  ╰ [1]: CWE-862 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ├ nvd    : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.4 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 4.1 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.4 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 4.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-2183 
│                       │      │                  ├ [1]: https://github.com/grafana/bugbounty 
│                       │      │                  ├ [2]: https://github.com/grafana/bugbounty/security/advisori
│                       │      │                  │      es/GHSA-cvm3-pp2j-chr3 
│                       │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2183 
│                       │      │                  ├ [4]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2183/ 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2023-2183 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20230706-0002/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-2183 
│                       │      ├ PublishedDate   : 2023-06-06T19:15:11.277Z 
│                       │      ╰ LastModifiedDate: 2025-02-13T17:16:19.957Z 
│                       ├ [22] ╭ VulnerabilityID : CVE-2023-4822 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-4822 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: incorrect assessment of permissions across
│                       │      │                   organizations 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. The vulnerability impacts Grafana instances
│                       │      │                   with several organizations, and allows a user with
│                       │      │                   Organization Admin permissions in one organization to change
│                       │      │                    the permissions associated with Organization Viewer,
│                       │      │                   Organization Editor and Organization Admin roles in all
│                       │      │                   organizations.
│                       │      │                   
│                       │      │                   It also allows an Organization Admin to assign or revoke any
│                       │      │                    permissions that they have to any user globally.
│                       │      │                   This means that any Organization Admin can elevate their own
│                       │      │                    permissions in any organization that they are already a
│                       │      │                   member of, or elevate or restrict the permissions of any
│                       │      │                   other user.
│                       │      │                   The vulnerability does not allow a user to become a member
│                       │      │                   of an organization that they are not already a member of, or
│                       │      │                    to add any other users to an organization that the current
│                       │      │                   user is not a member of. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-269 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 3 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 6.7 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.2 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 6.7 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-4822 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://grafana.com/blog/2023/10/13/grafana-security-r
│                       │      │                  │      elease-new-versions-of-grafana-with-a-medium-severity-
│                       │      │                  │      security-fix-for-cve-2023-4822/ 
│                       │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-4822 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2023-4822 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20231103-0008 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20231103-0008/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-4822 
│                       │      ├ PublishedDate   : 2023-10-16T09:15:11.687Z 
│                       │      ╰ LastModifiedDate: 2025-06-16T17:15:27.72Z 
│                       ├ [23] ╭ VulnerabilityID : CVE-2025-3415 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : 200a0142000fee77 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 1.9.2-0.20250514160932-04111e9f2afd 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-3415 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Exposure of DingDing alerting integration URL to
│                       │      │                   Viewer level users 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. The Grafana Alerting DingDing integration was
│                       │      │                    not properly protected and could be exposed to users with
│                       │      │                   Viewer permission. 
│                       │      │                   Fixed in versions 10.4.19+security-01, 11.2.10+security-01,
│                       │      │                   11.3.7+security-01, 11.4.5+security-01, 11.5.5+security-01,
│                       │      │                   11.6.2+security-01 and 12.0.1+security-01 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-200 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 4.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2025-3415 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/commit/04111e9f2af
│                       │      │                  │       d95ea3e5b01865cc29d3fc1198e71 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/0adb869188f
│                       │      │                  │       a2b9ae26efd424b94e17189538f29 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/19c912476d4
│                       │      │                  │       f7a81e8a3562668bc38f31b909e18 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/commit/4144c636d1a
│                       │      │                  │       6d0b17fafcf7a2c40fa403542202a 
│                       │      │                  ├ [6] : https://github.com/grafana/grafana/commit/4fc33647a82
│                       │      │                  │       97d3a0aae04a5fcbac883ceb6a655 
│                       │      │                  ├ [7] : https://github.com/grafana/grafana/commit/910eb1dd9e6
│                       │      │                  │       18014c6b1d2a99a431b99d4268c05 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana/commit/91327938626
│                       │      │                  │       c9426e481e6294850af7b61415c98 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/commit/a78de30720b
│                       │      │                  │       4f33c88d0c1a973e693ebf3831717 
│                       │      │                  ├ [10]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2025-3415 
│                       │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2025-3415 
│                       │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2025-3415 
│                       │      ├ PublishedDate   : 2025-07-17T11:15:22.24Z 
│                       │      ╰ LastModifiedDate: 2025-07-17T21:15:50.197Z 
│                       ╰ [24] ╭ VulnerabilityID : CVE-2024-10452 
│                              ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                              │                   6+dirty 
│                              ├ PkgName         : github.com/grafana/grafana 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                              │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                              │                  ╰ UID : 200a0142000fee77 
│                              ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                              │                  │         f0cd2bf50b021cbc8562 
│                              │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                              │                            a26c555f5f835bf9a62c 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-10452 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Title           : grafana: Org admin can delete pending invites in different org 
│                              ├ Description     : Organization admins can delete pending invites created in an
│                              │                    organization they are not part of. 
│                              ├ Severity        : LOW 
│                              ├ CweIDs           ─ [0]: CWE-639 
│                              ├ VendorSeverity   ╭ bitnami: 1 
│                              │                  ├ ghsa   : 1 
│                              │                  ├ nvd    : 1 
│                              │                  ╰ redhat : 1 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 2.7 
│                              │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 2.2 
│                              │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 2.7 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 2.2 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2024-10452 
│                              │                  ├ [1]: https://github.com/advisories/GHSA-66c4-2g2v-54qw 
│                              │                  ├ [2]: https://github.com/grafana/grafana 
│                              │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                              │                  │      024-10452 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2024-10452 
│                              │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2024-10452 
│                              ├ PublishedDate   : 2024-10-29T16:15:04.593Z 
│                              ╰ LastModifiedDate: 2024-11-08T17:59:10.977Z 
├ [7] ╭ Target         : usr/share/grafana/bin/grafana-cli 
│     ├ Class          : lang-pkgs 
│     ├ Type           : gobinary 
│     ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2018-15727 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 4.6.4, 5.2.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-15727 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: authentication bypass  knowing only a username of
│                       │      │                   an LDAP or OAuth user 
│                       │      ├ Description     : Grafana 2.x, 3.x, and 4.x before 4.6.4 and 5.x before 5.2.3
│                       │      │                   allows authentication bypass because an attacker can
│                       │      │                   generate a valid "remember me" cookie knowing only a
│                       │      │                   username of an LDAP or OAuth user. 
│                       │      ├ Severity        : CRITICAL 
│                       │      ├ CweIDs           ─ [0]: CWE-287 
│                       │      ├ VendorSeverity   ╭ ghsa  : 4 
│                       │      │                  ├ nvd   : 4 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 1 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:N/C:P/I:P/A:P 
│                       │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ├ V2Score : 7.5 
│                       │      │                  │        ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 5.5 
│                       │      ├ References       ╭ [0] : http://www.securityfocus.com/bid/105184 
│                       │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2018:3829 
│                       │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2019:0019 
│                       │      │                  ├ [3] : https://access.redhat.com/security/cve/CVE-2018-15727 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/7baecf0d0de
│                       │      │                  │       ae0d865e45cf03e082bc0db3f28c3 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/commit/df83bf10a22
│                       │      │                  │       5811927644bdf6265fa80bdea9137 
│                       │      │                  ├ [6] : https://grafana.com/blog/2018/08/29/grafana-5.2.3-and
│                       │      │                  │       -4.6.4-released-with-important-security-fix 
│                       │      │                  ├ [7] : https://grafana.com/blog/2018/08/29/grafana-5.2.3-and
│                       │      │                  │       -4.6.4-released-with-important-security-fix/ 
│                       │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2018-15727 
│                       │      │                  ├ [9] : https://www.cve.org/CVERecord?id=CVE-2018-15727 
│                       │      │                  ╰ [10]: https://www.securityfocus.com/bid/105184 
│                       │      ├ PublishedDate   : 2018-08-29T15:29:00.24Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:51:20.95Z 
│                       ├ [1]  ╭ VulnerabilityID : CVE-2023-3128 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.4.13, 9.3.16, 9.2.20, 8.5.27 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-3128 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: account takeover possible when using Azure AD OAuth 
│                       │      ├ Description     : Grafana is validating Azure AD accounts based on the email
│                       │      │                   claim. 
│                       │      │                   
│                       │      │                   On Azure AD, the profile email field is not unique and can
│                       │      │                   be easily modified. 
│                       │      │                   This leads to account takeover and authentication bypass
│                       │      │                   when Azure AD OAuth is configured with a multi-tenant app. 
│                       │      ├ Severity        : CRITICAL 
│                       │      ├ CweIDs           ─ [0]: CWE-290 
│                       │      ├ VendorSeverity   ╭ alma       : 4 
│                       │      │                  ├ bitnami    : 4 
│                       │      │                  ├ ghsa       : 4 
│                       │      │                  ├ nvd        : 4 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ rocky      : 4 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 9.8 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:L 
│                       │      │                  │         ╰ V3Score : 9.4 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 9.8 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           H/A:H 
│                       │      │                            ╰ V3Score : 9.8 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:4030 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2023-3128 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2213626 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2213626 
│                       │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
│                       │      │                  │       23-3128 
│                       │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2023-4030.html 
│                       │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2023:4030 
│                       │      │                  ├ [7] : https://github.com/grafana/bugbounty/security/advisor
│                       │      │                  │       ies/GHSA-gxh2-6vvc-rrgp 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/blob/69fc4e6bc0be2
│                       │      │                  │       a82085ab3885c2262a4d49e97d8/CHANGELOG.md 
│                       │      │                  ├ [10]: https://grafana.com/blog/2023/06/22/grafana-security-
│                       │      │                  │       release-for-cve-2023-3128/ 
│                       │      │                  ├ [11]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2023-3128 
│                       │      │                  ├ [12]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2023-3128/ 
│                       │      │                  ├ [13]: https://linux.oracle.com/cve/CVE-2023-3128.html 
│                       │      │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2023-6972.html 
│                       │      │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2023-3128 
│                       │      │                  ├ [16]: https://security.netapp.com/advisory/ntap-20230714-0004 
│                       │      │                  ├ [17]: https://security.netapp.com/advisory/ntap-20230714-00
│                       │      │                  │       04/ 
│                       │      │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2023-3128 
│                       │      ├ PublishedDate   : 2023-06-22T21:15:09.573Z 
│                       │      ╰ LastModifiedDate: 2025-02-13T17:16:55.49Z 
│                       ├ [2]  ╭ VulnerabilityID : CVE-2020-12458 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.2.1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-12458 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: information disclosure through world-readable
│                       │      │                   /var/lib/grafana/grafana.db 
│                       │      ├ Description     : An information-disclosure flaw was found in Grafana through
│                       │      │                   6.7.3. The database directory /var/lib/grafana and database
│                       │      │                   file /var/lib/grafana/grafana.db are world readable. This
│                       │      │                   can result in exposure of sensitive information (e.g.,
│                       │      │                   cleartext or encrypted datasource passwords). 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-732 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.5 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:L/AC:L/Au:N/C:P/I:N/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ├ V2Score : 2.1 
│                       │      │                  │         ╰ V3Score : 5.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 6.2 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-12458 
│                       │      │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=1827765 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/102448040d5
│                       │      │                  │       132460e3b0013e03ebedec0677e00 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/issues/8283 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-12458.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/CTQCKJZZY
│                       │      │                  │       XMCSHJFZZ3YXEO5NUBANGZS/ 
│                       │      │                  ├ [8] : https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/WEBCIEVSY
│                       │      │                  │       IDDCA7FTRS2IFUOYLIQU34A/ 
│                       │      │                  ├ [9] : https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/CTQCKJZZYXM
│                       │      │                  │       CSHJFZZ3YXEO5NUBANGZS 
│                       │      │                  ├ [10]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/WEBCIEVSYID
│                       │      │                  │       DCA7FTRS2IFUOYLIQU34A 
│                       │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2020-12458 
│                       │      │                  ├ [12]: https://security.netapp.com/advisory/ntap-20200518-0001 
│                       │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-20200518-00
│                       │      │                  │       01/ 
│                       │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2020-12458 
│                       │      ├ PublishedDate   : 2020-04-29T16:15:11.76Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:59:44.517Z 
│                       ├ [3]  ╭ VulnerabilityID : CVE-2021-39226 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.5.11, 8.1.6 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2021-39226 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Snapshot authentication bypass 
│                       │      ├ Description     : Grafana is an open source data visualization platform. In
│                       │      │                   affected versions unauthenticated and authenticated users
│                       │      │                   are able to view the snapshot with the lowest database key
│                       │      │                   by accessing the literal paths: /dashboard/snapshot/:key, or
│                       │      │                    /api/snapshots/:key. If the snapshot "public_mode"
│                       │      │                   configuration setting is set to true (vs default of false),
│                       │      │                   unauthenticated users are able to delete the snapshot with
│                       │      │                   the lowest database key by accessing the literal path:
│                       │      │                   /api/snapshots-delete/:deleteKey. Regardless of the snapshot
│                       │      │                    "public_mode" setting, authenticated users are able to
│                       │      │                   delete the snapshot with the lowest database key by
│                       │      │                   accessing the literal paths: /api/snapshots/:key, or
│                       │      │                   /api/snapshots-delete/:deleteKey. The combination of
│                       │      │                   deletion and viewing enables a complete walk through all
│                       │      │                   snapshot data while resulting in complete snapshot data
│                       │      │                   loss. This issue has been resolved in versions 8.1.6 and
│                       │      │                   7.5.11. If for some reason you cannot upgrade you can use a
│                       │      │                   reverse proxy or similar to block access to the literal
│                       │      │                   paths: /api/snapshots/:key,
│                       │      │                   /api/snapshots-delete/:deleteKey, /dashboard/snapshot/:key,
│                       │      │                   and /api/snapshots/:key. They have no normal function and
│                       │      │                   can be disabled without side effects. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-287 
│                       │      │                  ╰ [1]: CWE-862 
│                       │      ├ VendorSeverity   ╭ bitnami    : 3 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 3 
│                       │      │                  ├ oracle-oval: 3 
│                       │      │                  ├ redhat     : 3 
│                       │      │                  ╰ rocky      : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.3 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:P/I:P/A:P 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ├ V2Score : 6.8 
│                       │      │                  │         ╰ V3Score : 7.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                            │           L/A:L 
│                       │      │                            ╰ V3Score : 7.3 
│                       │      ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2021/10/05/4 
│                       │      │                  ├ [1] : https://access.redhat.com/hydra/rest/securitydata/cve
│                       │      │                  │       /CVE-2021-39226.json 
│                       │      │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2021-39226 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/2d456a63758
│                       │      │                  │       55364d098ede379438bf7f0667269 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-69j6-29vr-p3j9 
│                       │      │                  ├ [6] : https://grafana.com/blog/2021/10/05/grafana-7.5.11-an
│                       │      │                  │       d-8.1.6-released-with-critical-security-fix/ 
│                       │      │                  ├ [7] : https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-7-5-11 
│                       │      │                  ├ [8] : https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-7-5-11/ 
│                       │      │                  ├ [9] : https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-8-1-6 
│                       │      │                  ├ [10]: https://grafana.com/docs/grafana/latest/release-notes
│                       │      │                  │       /release-notes-8-1-6/ 
│                       │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2021-39226.html 
│                       │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2021-3771.html 
│                       │      │                  ├ [13]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/DCKBFUSY6
│                       │      │                  │       V4VU5AQUYWKISREZX5NLQJT 
│                       │      │                  ├ [14]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/DCKBFUSY6
│                       │      │                  │       V4VU5AQUYWKISREZX5NLQJT/ 
│                       │      │                  ├ [15]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/E6ANHRDBX
│                       │      │                  │       QT6TURLP2THM26ZPDINFBEG 
│                       │      │                  ├ [16]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/E6ANHRDBX
│                       │      │                  │       QT6TURLP2THM26ZPDINFBEG/ 
│                       │      │                  ├ [17]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/DCKBFUSY6V4
│                       │      │                  │       VU5AQUYWKISREZX5NLQJT 
│                       │      │                  ├ [18]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/E6ANHRDBXQT
│                       │      │                  │       6TURLP2THM26ZPDINFBEG 
│                       │      │                  ├ [19]: https://nvd.nist.gov/vuln/detail/CVE-2021-39226 
│                       │      │                  ├ [20]: https://security.netapp.com/advisory/ntap-20211029-0008 
│                       │      │                  ├ [21]: https://security.netapp.com/advisory/ntap-20211029-00
│                       │      │                  │       08/ 
│                       │      │                  ├ [22]: https://www.cisa.gov/known-exploited-vulnerabilities-
│                       │      │                  │       catalog 
│                       │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2021-39226 
│                       │      ├ PublishedDate   : 2021-10-05T18:15:07.947Z 
│                       │      ╰ LastModifiedDate: 2025-02-18T14:53:42.247Z 
│                       ├ [4]  ╭ VulnerabilityID : CVE-2022-35957 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.1.6, 9.0.9, 8.5.13 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-35957 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Escalation from admin to server admin when auth
│                       │      │                   proxy is used 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. Versions prior to 9.1.6 and 8.5.13 are
│                       │      │                   vulnerable to an escalation from admin to server admin when
│                       │      │                   auth proxy is used, allowing an admin to take over the
│                       │      │                   server admin account and gain full control of the grafana
│                       │      │                   instance. All installations should be upgraded as soon as
│                       │      │                   possible. As a workaround deactivate auth proxy following
│                       │      │                   the instructions at:
│                       │      │                   https://grafana.com/docs/grafana/latest/setup-grafana/config
│                       │      │                   ure-security/configure-authentication/auth-proxy/ 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ─ [0]: CWE-290 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 6.6 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 6.6 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                  │         │           H/A:H 
│                       │      │                  │         ╰ V3Score : 6.6 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
│                       │      │                            │           H/A:H 
│                       │      │                            ╰ V3Score : 6.6 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:2167 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-35957 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2124669 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2125514 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131149 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2132868 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2132872 
│                       │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2023-2167.html 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-ff5c-938w-8c9q 
│                       │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2022-35957.html 
│                       │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2023-2167.html 
│                       │      │                  ├ [12]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce%40lists.fedoraproject.org/message/WYU5C2RIT
│                       │      │                  │       LHVZSTCWNGQWA6KSPYNXM2H/ 
│                       │      │                  ├ [13]: https://lists.fedoraproject.org/archives/list/package
│                       │      │                  │       -announce@lists.fedoraproject.org/message/WYU5C2RITLH
│                       │      │                  │       VZSTCWNGQWA6KSPYNXM2H 
│                       │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2022-35957 
│                       │      │                  ├ [15]: https://security.netapp.com/advisory/ntap-20221215-0001 
│                       │      │                  ├ [16]: https://security.netapp.com/advisory/ntap-20221215-00
│                       │      │                  │       01/ 
│                       │      │                  ╰ [17]: https://www.cve.org/CVERecord?id=CVE-2022-35957 
│                       │      ├ PublishedDate   : 2022-09-20T23:15:09.457Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:12:03.05Z 
│                       ├ [5]  ╭ VulnerabilityID : CVE-2022-39307 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.2.4, 8.5.15 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39307 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: User enumeration via forget password 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. When using the forget password on the login
│                       │      │                   page, a POST request is made to the
│                       │      │                   `/api/user/password/sent-reset-email` URL. When the username
│                       │      │                    or email does not exist, a JSON response contains a “user
│                       │      │                   not found” message. This leaks information to
│                       │      │                   unauthenticated users and introduces a security risk. This
│                       │      │                   issue has been patched in 9.2.4 and backported to 8.5.15.
│                       │      │                   There are no known workarounds. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-200 
│                       │      │                  ╰ [1]: CWE-209 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 3 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
│                       │      │                  │         │           H/A:L 
│                       │      │                  │         ╰ V3Score : 6.7 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 5.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:6420 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39307 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2131146 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2131147 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131148 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2138014 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2138015 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2148252 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/2158420 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/2161274 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/2184483 
│                       │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2023-6420.html 
│                       │      │                  ├ [12]: https://github.com/grafana/grafana 
│                       │      │                  ├ [13]: https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-3p62-42x7-gxg5 
│                       │      │                  ├ [14]: https://grafana.com/blog/2022/11/08/security-release-
│                       │      │                  │       new-versions-of-grafana-with-critical-and-moderate-fi
│                       │      │                  │       xes-for-cve-2022-39328-cve-2022-39307-and-cve-2022-39
│                       │      │                  │       306/ 
│                       │      │                  ├ [15]: https://linux.oracle.com/cve/CVE-2022-39307.html 
│                       │      │                  ├ [16]: https://linux.oracle.com/errata/ELSA-2023-6420.html 
│                       │      │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2022-39307 
│                       │      │                  ├ [18]: https://security.netapp.com/advisory/ntap-20221215-0004 
│                       │      │                  ├ [19]: https://security.netapp.com/advisory/ntap-20221215-00
│                       │      │                  │       04/ 
│                       │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2022-39307 
│                       │      ├ PublishedDate   : 2022-11-09T23:15:12.617Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:18:00.08Z 
│                       ├ [6]  ╭ VulnerabilityID : CVE-2023-2801 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.4.12, 9.5.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-2801 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: data source proxy race condition 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. 
│                       │      │                   
│                       │      │                   Using public dashboards users can query multiple distinct
│                       │      │                   data sources using mixed queries. However such query has a
│                       │      │                   possibility of crashing a Grafana instance.
│                       │      │                   The only feature that uses mixed queries at the moment is
│                       │      │                   public dashboards, but it's also possible to cause this by
│                       │      │                   calling the query API directly.
│                       │      │                   This might enable malicious users to crash Grafana instances
│                       │      │                    through that endpoint.
│                       │      │                   Users may upgrade to version 9.4.12 and 9.5.3 to receive a
│                       │      │                   fix. 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-820 
│                       │      │                  ╰ [1]: CWE-662 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ├ nvd    : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 7.5 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:H 
│                       │      │                  │         ╰ V3Score : 5.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:H 
│                       │      │                            ╰ V3Score : 7.5 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-2801 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2801 
│                       │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2801/ 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2023-2801 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20230706-0002 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20230706-0002/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-2801 
│                       │      ├ PublishedDate   : 2023-06-06T19:15:11.413Z 
│                       │      ╰ LastModifiedDate: 2025-02-13T17:16:22.81Z 
│                       ├ [7]  ╭ VulnerabilityID : CVE-2025-6023 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 1.9.2-0.20250521205822-0ba0b99665a9 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-6023 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Cross Site Scripting in Grafana 
│                       │      ├ Description     : An open redirect vulnerability has been identified in
│                       │      │                   Grafana OSS that can be exploited to achieve XSS attacks.
│                       │      │                   The vulnerability was introduced in Grafana v11.5.0.
│                       │      │                   
│                       │      │                   The open redirect can be chained with path traversal
│                       │      │                   vulnerabilities to achieve XSS.
│                       │      │                   Fixed in versions 12.0.2+security-01, 11.6.3+security-01,
│                       │      │                   11.5.6+security-01, 11.4.6+security-01 and 11.3.8+security-0
│                       │      │                   1 
│                       │      ├ Severity        : HIGH 
│                       │      ├ CweIDs           ╭ [0]: CWE-79 
│                       │      │                  ╰ [1]: CWE-601 
│                       │      ├ VendorSeverity   ╭ bitnami: 3 
│                       │      │                  ├ ghsa   : 3 
│                       │      │                  ╰ redhat : 3 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.6 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
│                       │      │                  │         │           L/A:L 
│                       │      │                  │         ╰ V3Score : 7.6 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 7.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2025-6023 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/commit/0ba0b99665a
│                       │      │                  │       946cd96676ef85ec8bc83028cb1d7 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/40ed88fe86d
│                       │      │                  │       347bcde5ddaed6c4a20a95d2f0d55 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/5b00e21638f
│                       │      │                  │       565eed46acb4d0b7c009968df4c3b 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/commit/b6dd2b70c65
│                       │      │                  │       5c61b111b328f1a7dcca6b3954936 
│                       │      │                  ├ [6] : https://github.com/grafana/grafana/commit/e0ba4b48095
│                       │      │                  │       4f8a33aa2cff3229f6bcc05777bd9 
│                       │      │                  ├ [7] : https://grafana.com/blog/2025/07/17/grafana-security-
│                       │      │                  │       release-medium-and-high-severity-fixes-for-cve-2025-6
│                       │      │                  │       197-and-cve-2025-6023 
│                       │      │                  ├ [8] : https://grafana.com/blog/2025/07/17/grafana-security-
│                       │      │                  │       release-medium-and-high-severity-fixes-for-cve-2025-6
│                       │      │                  │       197-and-cve-2025-6023/ 
│                       │      │                  ├ [9] : https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2025-6023 
│                       │      │                  ├ [10]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2025-6023/ 
│                       │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2025-6023 
│                       │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2025-6023 
│                       │      ├ PublishedDate   : 2025-07-18T08:15:28.04Z 
│                       │      ╰ LastModifiedDate: 2025-07-22T13:06:27.983Z 
│                       ├ [8]  ╭ VulnerabilityID : CVE-2018-1000816 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 5.3.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-1000816 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Cross site scripting in Influxdb and Graphite query
│                       │      │                    editor 
│                       │      ├ Description     : Grafana version confirmed for 5.2.4 and 5.3.0 contains a
│                       │      │                   Cross Site Scripting (XSS) vulnerability in Influxdb and
│                       │      │                   Graphite query editor that can result in Running arbitrary
│                       │      │                   js code in victims browser.. This attack appear to be
│                       │      │                   exploitable via Authenticated user must click on the input
│                       │      │                   field where the payload was previously inserted.. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 5.4 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:S/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 3.5 
│                       │      │                  │        ╰ V3Score : 5.4 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 5.4 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-1000816 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/commit/eabb04cec21d
│                       │      │                  │      c323347da1aab7fcbf2a6e9dd121 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/issues/13667 
│                       │      │                  ├ [4]: https://github.com/grafana/grafana/pull/13670 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2018-1000816 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2018-1000816 
│                       │      ├ PublishedDate   : 2018-12-20T15:29:00.643Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:40:25.107Z 
│                       ├ [9]  ╭ VulnerabilityID : CVE-2018-12099 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 5.2.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-12099 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Cross-site Scripting (XSS) in dashboard links 
│                       │      ├ Description     : Grafana before 5.2.0-beta1 has XSS vulnerabilities in
│                       │      │                   dashboard links. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 1 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.8 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-12099 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/releases/tag/v5.2.0
│                       │      │                  │      -beta1 
│                       │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2018-12099 
│                       │      │                  ├ [4]: https://security.netapp.com/advisory/ntap-20190416-0004 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20190416-0004/ 
│                       │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2018-12099 
│                       │      ├ PublishedDate   : 2018-06-11T11:29:00.413Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:44:35.77Z 
│                       ├ [10] ╭ VulnerabilityID : CVE-2018-18623 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.0.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18623 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS vulnerability via the "Dashboard > Text Panel"
│                       │      │                   screen 
│                       │      ├ Description     : Grafana 5.3.1 has XSS via the "Dashboard > Text Panel"
│                       │      │                   screen. NOTE: this issue exists because of an incomplete fix
│                       │      │                    for CVE-2018-12099. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-18623 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana/issues/15293 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/issues/4117 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [4]: https://github.com/grafana/grafana/pull/14984 
│                       │      │                  ├ [5]: https://github.com/grafana/grafana/releases/tag/v6.0.0 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2018-18623 
│                       │      │                  ├ [7]: https://security.netapp.com/advisory/ntap-20200608-0008 
│                       │      │                  ├ [8]: https://security.netapp.com/advisory/ntap-20200608-0008/ 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2018-18623 
│                       │      ├ PublishedDate   : 2020-06-02T17:15:11.427Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:56:15.137Z 
│                       ├ [11] ╭ VulnerabilityID : CVE-2018-18624 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.0.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18624 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS vulnerability via a column style on the
│                       │      │                   "Dashboard > Table Panel" screen 
│                       │      ├ Description     : Grafana 5.3.1 has XSS via a column style on the "Dashboard >
│                       │      │                    Table Panel" screen. NOTE: this issue exists because of an
│                       │      │                   incomplete fix for CVE-2018-12099. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2018-18624 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/commit/0284747c88e
│                       │      │                  │       b9435899006d26ffaf65f89dec88e 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/pull/23816 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2018-18624.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2018-18624 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200608-0008 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200608-00
│                       │      │                  │       08/ 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2018-18624 
│                       │      ├ PublishedDate   : 2020-06-02T17:15:11.487Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:56:15.3Z 
│                       ├ [12] ╭ VulnerabilityID : CVE-2018-18625 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.0.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18625 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS vulnerability via a link on the "Dashboard >
│                       │      │                   All Panels > General" screen 
│                       │      ├ Description     : Grafana 5.3.1 has XSS via a link on the "Dashboard > All
│                       │      │                   Panels > General" screen. NOTE: this issue exists because of
│                       │      │                    an incomplete fix for CVE-2018-12099. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 2 
│                       │      │                  ├ redhat: 2 
│                       │      │                  ╰ ubuntu: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4.3 
│                       │      │                  │        ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-18625 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana/pull/11813 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/pull/14984 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/pull/22680#issuecom
│                       │      │                  │      ment-651195921 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2018-18625 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20200608-0008 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20200608-0008/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2018-18625 
│                       │      ├ PublishedDate   : 2020-06-02T17:15:11.567Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T03:56:15.443Z 
│                       ├ [13] ╭ VulnerabilityID : CVE-2019-13068 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.2.5 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-13068 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : Grafana Cross-site Scripting vulnerability 
│                       │      ├ Description     : public/app/features/panel/panel_ctrl.ts in Grafana before
│                       │      │                   6.2.5 allows HTML Injection in panel drilldown links (via
│                       │      │                   the Title or url field). 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ ghsa: 2 
│                       │      │                  ╰ nvd : 2 
│                       │      ├ CVSS             ╭ ghsa ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N 
│                       │      │                  │      ╰ V3Score : 5.4 
│                       │      │                  ╰ nvd  ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                         ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N 
│                       │      │                         ├ V2Score : 4.3 
│                       │      │                         ╰ V3Score : 5.4 
│                       │      ├ References       ╭ [0]: http://packetstormsecurity.com/files/171500/Grafana-6.
│                       │      │                  │      2.4-HTML-Injection.html 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/issues/17718 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/releases/tag/v6.2.5 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2019-13068 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20190710-0001 
│                       │      │                  ╰ [6]: https://security.netapp.com/advisory/ntap-20190710-0001/ 
│                       │      ├ PublishedDate   : 2019-06-30T00:15:11.313Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:24:08.057Z 
│                       ├ [14] ╭ VulnerabilityID : CVE-2019-19499 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.4.4 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-19499 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: arbitrary file read via MySQL data source 
│                       │      ├ Description     : Grafana <= 6.4.3 has an Arbitrary File Read vulnerability,
│                       │      │                   which could be exploited by an authenticated attacker that
│                       │      │                   has privileges to modify the data source configurations. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-89 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                  │        │           /A:N/E:P 
│                       │      │                  │        ╰ V3Score : 6.2 
│                       │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:S/C:P/I:N/A:N 
│                       │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                  │        │           /A:N 
│                       │      │                  │        ├ V2Score : 4 
│                       │      │                  │        ╰ V3Score : 6.5 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
│                       │      │                           │           /A:N 
│                       │      │                           ╰ V3Score : 6.5 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2019-19499 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/blob/master/CHANGE
│                       │      │                  │       LOG.md#644-2019-11-06 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/19dbd27c5ca
│                       │      │                  │       a1a160bd5854b65a4e1fe2a8a4f00 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/pull/20192 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2019-19499.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2019-19499 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200918-0003 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200918-00
│                       │      │                  │       03/ 
│                       │      │                  ├ [10]: https://swarm.ptsecurity.com/grafana-6-4-3-arbitrary-
│                       │      │                  │       file-read/ 
│                       │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2019-19499 
│                       │      ├ PublishedDate   : 2020-08-28T15:15:11.953Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:34:50.603Z 
│                       ├ [15] ╭ VulnerabilityID : CVE-2020-11110 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.7.2 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-11110 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: stored XSS 
│                       │      ├ Description     : Grafana through 6.7.1 allows stored XSS due to insufficient
│                       │      │                   input protection in the originalUrl field, which allows an
│                       │      │                   attacker to inject JavaScript code that will be executed
│                       │      │                   after clicking on Open Original Dashboard after visiting the
│                       │      │                    snapshot. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 5.4 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 5.4 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:S/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 3.5 
│                       │      │                  │         ╰ V3Score : 5.4 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-11110 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/blob/master/CHANGE
│                       │      │                  │       LOG.md 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/fb114a75241
│                       │      │                  │       aaef4c08581b42509c750738b768a 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/pull/23254 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-11110.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2020-11110 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200810-0002 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200810-00
│                       │      │                  │       02/ 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2020-11110 
│                       │      ├ PublishedDate   : 2020-07-27T13:15:11.293Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:56:48.55Z 
│                       ├ [16] ╭ VulnerabilityID : CVE-2020-12245 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 6.7.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-12245 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS via column.title or cellLinkTooltip 
│                       │      ├ Description     : Grafana before 6.7.3 allows table-panel XSS via column.title
│                       │      │                    or cellLinkTooltip. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 4.3 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-06/msg00060.html 
│                       │      │                  ├ [1] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-07/msg00083.html 
│                       │      │                  ├ [2] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-10/msg00009.html 
│                       │      │                  ├ [3] : http://lists.opensuse.org/opensuse-security-announce/
│                       │      │                  │       2020-10/msg00017.html 
│                       │      │                  ├ [4] : https://access.redhat.com/security/cve/CVE-2020-12245 
│                       │      │                  ├ [5] : https://community.grafana.com/t/release-notes-v6-7-x/
│                       │      │                  │       27119 
│                       │      │                  ├ [6] : https://github.com/grafana/grafana 
│                       │      │                  ├ [7] : https://github.com/grafana/grafana/blob/master/CHANGE
│                       │      │                  │       LOG.md#673-2020-04-23 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana/commit/0284747c88e
│                       │      │                  │       b9435899006d26ffaf65f89dec88e 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/pull/23816 
│                       │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2020-12245.html 
│                       │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2020-12245 
│                       │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-20200511-0001 
│                       │      │                  ├ [14]: https://security.netapp.com/advisory/ntap-20200511-00
│                       │      │                  │       01/ 
│                       │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2020-12245 
│                       │      ├ PublishedDate   : 2020-04-24T21:15:13.92Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T04:59:22.397Z 
│                       ├ [17] ╭ VulnerabilityID : CVE-2020-13430 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.0.0 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-13430 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS via the OpenTSDB datasource 
│                       │      ├ Description     : Grafana before 7.0.0 allows tag value XSS via the OpenTSDB
│                       │      │                   datasource. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 4.3 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-13430 
│                       │      │                  ├ [1] : https://github.com/advisories/GHSA-7m2x-qhrq-rp8h 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/pull/24539 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/releases/tag/v7.0.0 
│                       │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-13430.html 
│                       │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
│                       │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2020-13430 
│                       │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200528-0003 
│                       │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200528-00
│                       │      │                  │       03/ 
│                       │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2020-13430 
│                       │      ├ PublishedDate   : 2020-05-24T18:15:10.097Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T05:01:14.78Z 
│                       ├ [18] ╭ VulnerabilityID : CVE-2020-24303 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 7.1.0-beta1 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-24303 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: XSS via a query alias for the Elasticsearch and
│                       │      │                   Testdata datasource 
│                       │      ├ Description     : Grafana before 7.1.0-beta 1 allows XSS via a query alias for
│                       │      │                    the ElasticSearch datasource. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
│                       │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ├ V2Score : 4.3 
│                       │      │                  │         ╰ V3Score : 6.1 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 6.1 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2020-24303 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://github.com/grafana/grafana/blob/master/CHANGEL
│                       │      │                  │      OG.md#710-beta-1-2020-07-01 
│                       │      │                  ├ [3]: https://github.com/grafana/grafana/pull/25401 
│                       │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2020-24303.html 
│                       │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2021-1859.html 
│                       │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2020-24303 
│                       │      │                  ├ [7]: https://security.netapp.com/advisory/ntap-20201123-0002 
│                       │      │                  ├ [8]: https://security.netapp.com/advisory/ntap-20201123-0002/ 
│                       │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2020-24303 
│                       │      ├ PublishedDate   : 2020-10-28T14:15:12.33Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T05:14:34.773Z 
│                       ├ [19] ╭ VulnerabilityID : CVE-2022-39229 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 8.5.14, 9.1.8 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39229 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: using email as a username can block other users
│                       │      │                   from signing in 
│                       │      ├ Description     : Grafana is an open source data visualization platform for
│                       │      │                   metrics, logs, and traces. Versions prior to 9.1.8 and
│                       │      │                   8.5.14 allow one user to block another user's login attempt
│                       │      │                   by registering someone else'e email address as a username. A
│                       │      │                    Grafana user’s username and email address are unique
│                       │      │                   fields, that means no other user can have the same username
│                       │      │                   or email address as another user. A user can have an email
│                       │      │                   address as a username. However, the login system allows
│                       │      │                   users to log in with either username or email address. Since
│                       │      │                    Grafana allows a user to log in with either their username
│                       │      │                   or email address, this creates an usual behavior where
│                       │      │                   `user_1` can register with one email address and `user_2`
│                       │      │                   can register their username as `user_1`’s email address.
│                       │      │                   This prevents `user_1` logging into the application since
│                       │      │                   `user_1`'s password won’t match with `user_2`'s email
│                       │      │                   address. Versions 9.1.8 and 8.5.14 contain a patch. There
│                       │      │                   are no workarounds for this issue. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-287 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 2 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 2 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 1 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:L 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:L 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                  │         │           N/A:L 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                            │           N/A:L 
│                       │      │                            ╰ V3Score : 4.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:2167 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39229 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2124669 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2125514 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131149 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2132868 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2132872 
│                       │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2023-2167.html 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/commit/5644758f0c5
│                       │      │                  │       ae9955a4e5480d71f9bef57fdce35 
│                       │      │                  ├ [10]: https://github.com/grafana/grafana/releases/tag/v9.1.8 
│                       │      │                  ├ [11]: https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-gj7m-853r-289r 
│                       │      │                  ├ [12]: https://linux.oracle.com/cve/CVE-2022-39229.html 
│                       │      │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2023-2784.html 
│                       │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2022-39229 
│                       │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2022-39229 
│                       │      ├ PublishedDate   : 2022-10-13T23:15:10.937Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:17:50.027Z 
│                       ├ [20] ╭ VulnerabilityID : CVE-2022-39324 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 9.2.8, 8.5.16 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39324 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Spoofing of the originalUrl parameter of snapshots 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. Prior to versions 8.5.16 and 9.2.8, malicious
│                       │      │                    user can create a snapshot and arbitrarily choose the
│                       │      │                   `originalUrl` parameter by editing the query, thanks to a
│                       │      │                   web proxy. When another user opens the URL of the snapshot,
│                       │      │                   they will be presented with the regular web interface
│                       │      │                   delivered by the trusted Grafana server. The `Open original
│                       │      │                   dashboard` button no longer points to the to the real
│                       │      │                   original dashboard but to the attacker’s injected URL. This
│                       │      │                   issue is fixed in versions 8.5.16 and 9.2.8. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-79 
│                       │      ├ VendorSeverity   ╭ alma       : 2 
│                       │      │                  ├ bitnami    : 1 
│                       │      │                  ├ ghsa       : 2 
│                       │      │                  ├ nvd        : 1 
│                       │      │                  ├ oracle-oval: 2 
│                       │      │                  ├ redhat     : 2 
│                       │      │                  ╰ ubuntu     : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 3.5 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
│                       │      │                  │         │           H/A:L 
│                       │      │                  │         ╰ V3Score : 6.7 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 3.5 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
│                       │      │                            │           H/A:L 
│                       │      │                            ╰ V3Score : 6.7 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:6420 
│                       │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39324 
│                       │      │                  ├ [2] : https://bugzilla.redhat.com/2131146 
│                       │      │                  ├ [3] : https://bugzilla.redhat.com/2131147 
│                       │      │                  ├ [4] : https://bugzilla.redhat.com/2131148 
│                       │      │                  ├ [5] : https://bugzilla.redhat.com/2138014 
│                       │      │                  ├ [6] : https://bugzilla.redhat.com/2138015 
│                       │      │                  ├ [7] : https://bugzilla.redhat.com/2148252 
│                       │      │                  ├ [8] : https://bugzilla.redhat.com/2158420 
│                       │      │                  ├ [9] : https://bugzilla.redhat.com/2161274 
│                       │      │                  ├ [10]: https://bugzilla.redhat.com/2184483 
│                       │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2023-6420.html 
│                       │      │                  ├ [12]: https://github.com/grafana/grafana 
│                       │      │                  ├ [13]: https://github.com/grafana/grafana/commit/239888f2298
│                       │      │                  │       3010576bb3a9135a7294e88c0c74a 
│                       │      │                  ├ [14]: https://github.com/grafana/grafana/commit/d7dcea71ea7
│                       │      │                  │       63780dc286792a0afd560bff2985c 
│                       │      │                  ├ [15]: https://github.com/grafana/grafana/pull/60232 
│                       │      │                  ├ [16]: https://github.com/grafana/grafana/pull/60256 
│                       │      │                  ├ [17]: https://github.com/grafana/grafana/security/advisorie
│                       │      │                  │       s/GHSA-4724-7jwc-3fpw 
│                       │      │                  ├ [18]: https://grafana.com/blog/2023/01/25/grafana-security-
│                       │      │                  │       releases-new-versions-with-fixes-for-cve-2022-23552-c
│                       │      │                  │       ve-2022-41912-and-cve-2022-39324/ 
│                       │      │                  ├ [19]: https://linux.oracle.com/cve/CVE-2022-39324.html 
│                       │      │                  ├ [20]: https://linux.oracle.com/errata/ELSA-2023-6420.html 
│                       │      │                  ├ [21]: https://nvd.nist.gov/vuln/detail/CVE-2022-39324 
│                       │      │                  ├ [22]: https://security.netapp.com/advisory/ntap-20230309-00
│                       │      │                  │       10/ 
│                       │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2022-39324 
│                       │      ├ PublishedDate   : 2023-01-27T23:15:08.723Z 
│                       │      ╰ LastModifiedDate: 2024-11-21T07:18:02.36Z 
│                       ├ [21] ╭ VulnerabilityID : CVE-2023-2183 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 8.5.26, 9.2.19, 9.3.15, 9.4.12, 9.5.3 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-2183 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: missing access control allows test alerts by
│                       │      │                   underprivileged user 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. 
│                       │      │                   
│                       │      │                   The option to send a test alert is not available from the
│                       │      │                   user panel UI for users having the Viewer role. It is still
│                       │      │                   possible for a user with the Viewer role to send a test
│                       │      │                   alert using the API as the API does not check access to this
│                       │      │                    function.
│                       │      │                   This might enable malicious users to abuse the functionality
│                       │      │                    by sending multiple alert messages to e-mail and Slack,
│                       │      │                   spamming users, prepare Phishing attack or block SMTP
│                       │      │                   server.
│                       │      │                   Users may upgrade to version 9.5.3, 9.4.12, 9.3.15, 9.2.19
│                       │      │                   and 8.5.26 to receive a fix. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ╭ [0]: CWE-284 
│                       │      │                  ╰ [1]: CWE-862 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ├ nvd    : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.4 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 4.1 
│                       │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:
│                       │      │                  │         │           L/A:N 
│                       │      │                  │         ╰ V3Score : 6.4 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
│                       │      │                            │           L/A:N 
│                       │      │                            ╰ V3Score : 4.3 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-2183 
│                       │      │                  ├ [1]: https://github.com/grafana/bugbounty 
│                       │      │                  ├ [2]: https://github.com/grafana/bugbounty/security/advisori
│                       │      │                  │      es/GHSA-cvm3-pp2j-chr3 
│                       │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2183 
│                       │      │                  ├ [4]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-2183/ 
│                       │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2023-2183 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20230706-0002/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-2183 
│                       │      ├ PublishedDate   : 2023-06-06T19:15:11.277Z 
│                       │      ╰ LastModifiedDate: 2025-02-13T17:16:19.957Z 
│                       ├ [22] ╭ VulnerabilityID : CVE-2023-4822 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ Status          : affected 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-4822 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: incorrect assessment of permissions across
│                       │      │                   organizations 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. The vulnerability impacts Grafana instances
│                       │      │                   with several organizations, and allows a user with
│                       │      │                   Organization Admin permissions in one organization to change
│                       │      │                    the permissions associated with Organization Viewer,
│                       │      │                   Organization Editor and Organization Admin roles in all
│                       │      │                   organizations.
│                       │      │                   
│                       │      │                   It also allows an Organization Admin to assign or revoke any
│                       │      │                    permissions that they have to any user globally.
│                       │      │                   This means that any Organization Admin can elevate their own
│                       │      │                    permissions in any organization that they are already a
│                       │      │                   member of, or elevate or restrict the permissions of any
│                       │      │                   other user.
│                       │      │                   The vulnerability does not allow a user to become a member
│                       │      │                   of an organization that they are not already a member of, or
│                       │      │                    to add any other users to an organization that the current
│                       │      │                   user is not a member of. 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-269 
│                       │      ├ VendorSeverity   ╭ ghsa  : 2 
│                       │      │                  ├ nvd   : 3 
│                       │      │                  ╰ redhat: 2 
│                       │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:L 
│                       │      │                  │        ╰ V3Score : 6.7 
│                       │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
│                       │      │                  │        │           /A:H 
│                       │      │                  │        ╰ V3Score : 7.2 
│                       │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
│                       │      │                           │           /A:L 
│                       │      │                           ╰ V3Score : 6.7 
│                       │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-4822 
│                       │      │                  ├ [1]: https://github.com/grafana/grafana 
│                       │      │                  ├ [2]: https://grafana.com/blog/2023/10/13/grafana-security-r
│                       │      │                  │      elease-new-versions-of-grafana-with-a-medium-severity-
│                       │      │                  │      security-fix-for-cve-2023-4822/ 
│                       │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                       │      │                  │      023-4822 
│                       │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2023-4822 
│                       │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20231103-0008 
│                       │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20231103-0008/ 
│                       │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-4822 
│                       │      ├ PublishedDate   : 2023-10-16T09:15:11.687Z 
│                       │      ╰ LastModifiedDate: 2025-06-16T17:15:27.72Z 
│                       ├ [23] ╭ VulnerabilityID : CVE-2025-3415 
│                       │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                       │      │                   6+dirty 
│                       │      ├ PkgName         : github.com/grafana/grafana 
│                       │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                       │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                       │      │                  ╰ UID : d6bcccd7fecead8 
│                       │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                       │      ├ FixedVersion    : 1.9.2-0.20250514160932-04111e9f2afd 
│                       │      ├ Status          : fixed 
│                       │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                       │      │                  │         f0cd2bf50b021cbc8562 
│                       │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                       │      │                            a26c555f5f835bf9a62c 
│                       │      ├ SeveritySource  : ghsa 
│                       │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-3415 
│                       │      ├ DataSource       ╭ ID  : ghsa 
│                       │      │                  ├ Name: GitHub Security Advisory Go 
│                       │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                       │      │                          cosystem%3Ago 
│                       │      ├ Title           : grafana: Exposure of DingDing alerting integration URL to
│                       │      │                   Viewer level users 
│                       │      ├ Description     : Grafana is an open-source platform for monitoring and
│                       │      │                   observability. The Grafana Alerting DingDing integration was
│                       │      │                    not properly protected and could be exposed to users with
│                       │      │                   Viewer permission. 
│                       │      │                   Fixed in versions 10.4.19+security-01, 11.2.10+security-01,
│                       │      │                   11.3.7+security-01, 11.4.5+security-01, 11.5.5+security-01,
│                       │      │                   11.6.2+security-01 and 12.0.1+security-01 
│                       │      ├ Severity        : MEDIUM 
│                       │      ├ CweIDs           ─ [0]: CWE-200 
│                       │      ├ VendorSeverity   ╭ bitnami: 2 
│                       │      │                  ├ ghsa   : 2 
│                       │      │                  ╰ redhat : 2 
│                       │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
│                       │      │                  │         │           N/A:N 
│                       │      │                  │         ╰ V3Score : 4.3 
│                       │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
│                       │      │                            │           N/A:N 
│                       │      │                            ╰ V3Score : 4.3 
│                       │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2025-3415 
│                       │      │                  ├ [1] : https://github.com/grafana/grafana 
│                       │      │                  ├ [2] : https://github.com/grafana/grafana/commit/04111e9f2af
│                       │      │                  │       d95ea3e5b01865cc29d3fc1198e71 
│                       │      │                  ├ [3] : https://github.com/grafana/grafana/commit/0adb869188f
│                       │      │                  │       a2b9ae26efd424b94e17189538f29 
│                       │      │                  ├ [4] : https://github.com/grafana/grafana/commit/19c912476d4
│                       │      │                  │       f7a81e8a3562668bc38f31b909e18 
│                       │      │                  ├ [5] : https://github.com/grafana/grafana/commit/4144c636d1a
│                       │      │                  │       6d0b17fafcf7a2c40fa403542202a 
│                       │      │                  ├ [6] : https://github.com/grafana/grafana/commit/4fc33647a82
│                       │      │                  │       97d3a0aae04a5fcbac883ceb6a655 
│                       │      │                  ├ [7] : https://github.com/grafana/grafana/commit/910eb1dd9e6
│                       │      │                  │       18014c6b1d2a99a431b99d4268c05 
│                       │      │                  ├ [8] : https://github.com/grafana/grafana/commit/91327938626
│                       │      │                  │       c9426e481e6294850af7b61415c98 
│                       │      │                  ├ [9] : https://github.com/grafana/grafana/commit/a78de30720b
│                       │      │                  │       4f33c88d0c1a973e693ebf3831717 
│                       │      │                  ├ [10]: https://grafana.com/security/security-advisories/cve-
│                       │      │                  │       2025-3415 
│                       │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2025-3415 
│                       │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2025-3415 
│                       │      ├ PublishedDate   : 2025-07-17T11:15:22.24Z 
│                       │      ╰ LastModifiedDate: 2025-07-17T21:15:50.197Z 
│                       ╰ [24] ╭ VulnerabilityID : CVE-2024-10452 
│                              ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
│                              │                   6+dirty 
│                              ├ PkgName         : github.com/grafana/grafana 
│                              ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
│                              │                  │       201843-ccd7b6ce7ea6%2Bdirty 
│                              │                  ╰ UID : d6bcccd7fecead8 
│                              ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
│                              ├ Status          : affected 
│                              ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
│                              │                  │         f0cd2bf50b021cbc8562 
│                              │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
│                              │                            a26c555f5f835bf9a62c 
│                              ├ SeveritySource  : ghsa 
│                              ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-10452 
│                              ├ DataSource       ╭ ID  : ghsa 
│                              │                  ├ Name: GitHub Security Advisory Go 
│                              │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
│                              │                          cosystem%3Ago 
│                              ├ Title           : grafana: Org admin can delete pending invites in different org 
│                              ├ Description     : Organization admins can delete pending invites created in an
│                              │                    organization they are not part of. 
│                              ├ Severity        : LOW 
│                              ├ CweIDs           ─ [0]: CWE-639 
│                              ├ VendorSeverity   ╭ bitnami: 1 
│                              │                  ├ ghsa   : 1 
│                              │                  ├ nvd    : 1 
│                              │                  ╰ redhat : 1 
│                              ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 2.7 
│                              │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 2.2 
│                              │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:
│                              │                  │         │           L/A:N 
│                              │                  │         ╰ V3Score : 2.7 
│                              │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:
│                              │                            │           L/A:N 
│                              │                            ╰ V3Score : 2.2 
│                              ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2024-10452 
│                              │                  ├ [1]: https://github.com/advisories/GHSA-66c4-2g2v-54qw 
│                              │                  ├ [2]: https://github.com/grafana/grafana 
│                              │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
│                              │                  │      024-10452 
│                              │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2024-10452 
│                              │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2024-10452 
│                              ├ PublishedDate   : 2024-10-29T16:15:04.593Z 
│                              ╰ LastModifiedDate: 2024-11-08T17:59:10.977Z 
╰ [8] ╭ Target         : usr/share/grafana/bin/grafana-server 
      ├ Class          : lang-pkgs 
      ├ Type           : gobinary 
      ╰ Vulnerabilities ╭ [0]  ╭ VulnerabilityID : CVE-2018-15727 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 4.6.4, 5.2.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-15727 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: authentication bypass  knowing only a username of
                        │      │                   an LDAP or OAuth user 
                        │      ├ Description     : Grafana 2.x, 3.x, and 4.x before 4.6.4 and 5.x before 5.2.3
                        │      │                   allows authentication bypass because an attacker can
                        │      │                   generate a valid "remember me" cookie knowing only a
                        │      │                   username of an LDAP or OAuth user. 
                        │      ├ Severity        : CRITICAL 
                        │      ├ CweIDs           ─ [0]: CWE-287 
                        │      ├ VendorSeverity   ╭ ghsa  : 4 
                        │      │                  ├ nvd   : 4 
                        │      │                  ├ redhat: 2 
                        │      │                  ╰ ubuntu: 1 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
                        │      │                  │        │           /A:H 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:N/C:P/I:P/A:P 
                        │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H
                        │      │                  │        │           /A:H 
                        │      │                  │        ├ V2Score : 7.5 
                        │      │                  │        ╰ V3Score : 9.8 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:L/I:L
                        │      │                           │           /A:L 
                        │      │                           ╰ V3Score : 5.5 
                        │      ├ References       ╭ [0] : http://www.securityfocus.com/bid/105184 
                        │      │                  ├ [1] : https://access.redhat.com/errata/RHSA-2018:3829 
                        │      │                  ├ [2] : https://access.redhat.com/errata/RHSA-2019:0019 
                        │      │                  ├ [3] : https://access.redhat.com/security/cve/CVE-2018-15727 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/commit/7baecf0d0de
                        │      │                  │       ae0d865e45cf03e082bc0db3f28c3 
                        │      │                  ├ [5] : https://github.com/grafana/grafana/commit/df83bf10a22
                        │      │                  │       5811927644bdf6265fa80bdea9137 
                        │      │                  ├ [6] : https://grafana.com/blog/2018/08/29/grafana-5.2.3-and
                        │      │                  │       -4.6.4-released-with-important-security-fix 
                        │      │                  ├ [7] : https://grafana.com/blog/2018/08/29/grafana-5.2.3-and
                        │      │                  │       -4.6.4-released-with-important-security-fix/ 
                        │      │                  ├ [8] : https://nvd.nist.gov/vuln/detail/CVE-2018-15727 
                        │      │                  ├ [9] : https://www.cve.org/CVERecord?id=CVE-2018-15727 
                        │      │                  ╰ [10]: https://www.securityfocus.com/bid/105184 
                        │      ├ PublishedDate   : 2018-08-29T15:29:00.24Z 
                        │      ╰ LastModifiedDate: 2024-11-21T03:51:20.95Z 
                        ├ [1]  ╭ VulnerabilityID : CVE-2023-3128 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 9.4.13, 9.3.16, 9.2.20, 8.5.27 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-3128 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: account takeover possible when using Azure AD OAuth 
                        │      ├ Description     : Grafana is validating Azure AD accounts based on the email
                        │      │                   claim. 
                        │      │                   
                        │      │                   On Azure AD, the profile email field is not unique and can
                        │      │                   be easily modified. 
                        │      │                   This leads to account takeover and authentication bypass
                        │      │                   when Azure AD OAuth is configured with a multi-tenant app. 
                        │      ├ Severity        : CRITICAL 
                        │      ├ CweIDs           ─ [0]: CWE-290 
                        │      ├ VendorSeverity   ╭ alma       : 4 
                        │      │                  ├ bitnami    : 4 
                        │      │                  ├ ghsa       : 4 
                        │      │                  ├ nvd        : 4 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ rocky      : 4 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 9.8 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:L 
                        │      │                  │         ╰ V3Score : 9.4 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 9.8 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                            │           H/A:H 
                        │      │                            ╰ V3Score : 9.8 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:4030 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2023-3128 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2213626 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/show_bug.cgi?id=2213626 
                        │      │                  ├ [4] : https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-20
                        │      │                  │       23-3128 
                        │      │                  ├ [5] : https://errata.almalinux.org/9/ALSA-2023-4030.html 
                        │      │                  ├ [6] : https://errata.rockylinux.org/RLSA-2023:4030 
                        │      │                  ├ [7] : https://github.com/grafana/bugbounty/security/advisor
                        │      │                  │       ies/GHSA-gxh2-6vvc-rrgp 
                        │      │                  ├ [8] : https://github.com/grafana/grafana 
                        │      │                  ├ [9] : https://github.com/grafana/grafana/blob/69fc4e6bc0be2
                        │      │                  │       a82085ab3885c2262a4d49e97d8/CHANGELOG.md 
                        │      │                  ├ [10]: https://grafana.com/blog/2023/06/22/grafana-security-
                        │      │                  │       release-for-cve-2023-3128/ 
                        │      │                  ├ [11]: https://grafana.com/security/security-advisories/cve-
                        │      │                  │       2023-3128 
                        │      │                  ├ [12]: https://grafana.com/security/security-advisories/cve-
                        │      │                  │       2023-3128/ 
                        │      │                  ├ [13]: https://linux.oracle.com/cve/CVE-2023-3128.html 
                        │      │                  ├ [14]: https://linux.oracle.com/errata/ELSA-2023-6972.html 
                        │      │                  ├ [15]: https://nvd.nist.gov/vuln/detail/CVE-2023-3128 
                        │      │                  ├ [16]: https://security.netapp.com/advisory/ntap-20230714-0004 
                        │      │                  ├ [17]: https://security.netapp.com/advisory/ntap-20230714-00
                        │      │                  │       04/ 
                        │      │                  ╰ [18]: https://www.cve.org/CVERecord?id=CVE-2023-3128 
                        │      ├ PublishedDate   : 2023-06-22T21:15:09.573Z 
                        │      ╰ LastModifiedDate: 2025-02-13T17:16:55.49Z 
                        ├ [2]  ╭ VulnerabilityID : CVE-2020-12458 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 7.2.1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-12458 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: information disclosure through world-readable
                        │      │                   /var/lib/grafana/grafana.db 
                        │      ├ Description     : An information-disclosure flaw was found in Grafana through
                        │      │                   6.7.3. The database directory /var/lib/grafana and database
                        │      │                   file /var/lib/grafana/grafana.db are world readable. This
                        │      │                   can result in exposure of sensitive information (e.g.,
                        │      │                   cleartext or encrypted datasource passwords). 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-732 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 3 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.5 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.5 
                        │      │                  ├ nvd     ╭ V2Vector: AV:L/AC:L/Au:N/C:P/I:N/A:N 
                        │      │                  │         ├ V3Vector: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ├ V2Score : 2.1 
                        │      │                  │         ╰ V3Score : 5.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 6.2 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-12458 
                        │      │                  ├ [1] : https://bugzilla.redhat.com/show_bug.cgi?id=1827765 
                        │      │                  ├ [2] : https://github.com/grafana/grafana 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/commit/102448040d5
                        │      │                  │       132460e3b0013e03ebedec0677e00 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/issues/8283 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-12458.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
                        │      │                  ├ [7] : https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/CTQCKJZZY
                        │      │                  │       XMCSHJFZZ3YXEO5NUBANGZS/ 
                        │      │                  ├ [8] : https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/WEBCIEVSY
                        │      │                  │       IDDCA7FTRS2IFUOYLIQU34A/ 
                        │      │                  ├ [9] : https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce@lists.fedoraproject.org/message/CTQCKJZZYXM
                        │      │                  │       CSHJFZZ3YXEO5NUBANGZS 
                        │      │                  ├ [10]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce@lists.fedoraproject.org/message/WEBCIEVSYID
                        │      │                  │       DCA7FTRS2IFUOYLIQU34A 
                        │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2020-12458 
                        │      │                  ├ [12]: https://security.netapp.com/advisory/ntap-20200518-0001 
                        │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-20200518-00
                        │      │                  │       01/ 
                        │      │                  ╰ [14]: https://www.cve.org/CVERecord?id=CVE-2020-12458 
                        │      ├ PublishedDate   : 2020-04-29T16:15:11.76Z 
                        │      ╰ LastModifiedDate: 2024-11-21T04:59:44.517Z 
                        ├ [3]  ╭ VulnerabilityID : CVE-2021-39226 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 7.5.11, 8.1.6 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2021-39226 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Snapshot authentication bypass 
                        │      ├ Description     : Grafana is an open source data visualization platform. In
                        │      │                   affected versions unauthenticated and authenticated users
                        │      │                   are able to view the snapshot with the lowest database key
                        │      │                   by accessing the literal paths: /dashboard/snapshot/:key, or
                        │      │                    /api/snapshots/:key. If the snapshot "public_mode"
                        │      │                   configuration setting is set to true (vs default of false),
                        │      │                   unauthenticated users are able to delete the snapshot with
                        │      │                   the lowest database key by accessing the literal path:
                        │      │                   /api/snapshots-delete/:deleteKey. Regardless of the snapshot
                        │      │                    "public_mode" setting, authenticated users are able to
                        │      │                   delete the snapshot with the lowest database key by
                        │      │                   accessing the literal paths: /api/snapshots/:key, or
                        │      │                   /api/snapshots-delete/:deleteKey. The combination of
                        │      │                   deletion and viewing enables a complete walk through all
                        │      │                   snapshot data while resulting in complete snapshot data
                        │      │                   loss. This issue has been resolved in versions 8.1.6 and
                        │      │                   7.5.11. If for some reason you cannot upgrade you can use a
                        │      │                   reverse proxy or similar to block access to the literal
                        │      │                   paths: /api/snapshots/:key,
                        │      │                   /api/snapshots-delete/:deleteKey, /dashboard/snapshot/:key,
                        │      │                   and /api/snapshots/:key. They have no normal function and
                        │      │                   can be disabled without side effects. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-287 
                        │      │                  ╰ [1]: CWE-862 
                        │      ├ VendorSeverity   ╭ bitnami    : 3 
                        │      │                  ├ ghsa       : 3 
                        │      │                  ├ nvd        : 3 
                        │      │                  ├ oracle-oval: 3 
                        │      │                  ├ redhat     : 3 
                        │      │                  ╰ rocky      : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           L/A:L 
                        │      │                  │         ╰ V3Score : 7.3 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           L/A:L 
                        │      │                  │         ╰ V3Score : 7.3 
                        │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:P/I:P/A:P 
                        │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           L/A:L 
                        │      │                  │         ├ V2Score : 6.8 
                        │      │                  │         ╰ V3Score : 7.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           L/A:L 
                        │      │                            ╰ V3Score : 7.3 
                        │      ├ References       ╭ [0] : http://www.openwall.com/lists/oss-security/2021/10/05/4 
                        │      │                  ├ [1] : https://access.redhat.com/hydra/rest/securitydata/cve
                        │      │                  │       /CVE-2021-39226.json 
                        │      │                  ├ [2] : https://access.redhat.com/security/cve/CVE-2021-39226 
                        │      │                  ├ [3] : https://github.com/grafana/grafana 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/commit/2d456a63758
                        │      │                  │       55364d098ede379438bf7f0667269 
                        │      │                  ├ [5] : https://github.com/grafana/grafana/security/advisorie
                        │      │                  │       s/GHSA-69j6-29vr-p3j9 
                        │      │                  ├ [6] : https://grafana.com/blog/2021/10/05/grafana-7.5.11-an
                        │      │                  │       d-8.1.6-released-with-critical-security-fix/ 
                        │      │                  ├ [7] : https://grafana.com/docs/grafana/latest/release-notes
                        │      │                  │       /release-notes-7-5-11 
                        │      │                  ├ [8] : https://grafana.com/docs/grafana/latest/release-notes
                        │      │                  │       /release-notes-7-5-11/ 
                        │      │                  ├ [9] : https://grafana.com/docs/grafana/latest/release-notes
                        │      │                  │       /release-notes-8-1-6 
                        │      │                  ├ [10]: https://grafana.com/docs/grafana/latest/release-notes
                        │      │                  │       /release-notes-8-1-6/ 
                        │      │                  ├ [11]: https://linux.oracle.com/cve/CVE-2021-39226.html 
                        │      │                  ├ [12]: https://linux.oracle.com/errata/ELSA-2021-3771.html 
                        │      │                  ├ [13]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/DCKBFUSY6
                        │      │                  │       V4VU5AQUYWKISREZX5NLQJT 
                        │      │                  ├ [14]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/DCKBFUSY6
                        │      │                  │       V4VU5AQUYWKISREZX5NLQJT/ 
                        │      │                  ├ [15]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/E6ANHRDBX
                        │      │                  │       QT6TURLP2THM26ZPDINFBEG 
                        │      │                  ├ [16]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/E6ANHRDBX
                        │      │                  │       QT6TURLP2THM26ZPDINFBEG/ 
                        │      │                  ├ [17]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce@lists.fedoraproject.org/message/DCKBFUSY6V4
                        │      │                  │       VU5AQUYWKISREZX5NLQJT 
                        │      │                  ├ [18]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce@lists.fedoraproject.org/message/E6ANHRDBXQT
                        │      │                  │       6TURLP2THM26ZPDINFBEG 
                        │      │                  ├ [19]: https://nvd.nist.gov/vuln/detail/CVE-2021-39226 
                        │      │                  ├ [20]: https://security.netapp.com/advisory/ntap-20211029-0008 
                        │      │                  ├ [21]: https://security.netapp.com/advisory/ntap-20211029-00
                        │      │                  │       08/ 
                        │      │                  ├ [22]: https://www.cisa.gov/known-exploited-vulnerabilities-
                        │      │                  │       catalog 
                        │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2021-39226 
                        │      ├ PublishedDate   : 2021-10-05T18:15:07.947Z 
                        │      ╰ LastModifiedDate: 2025-02-18T14:53:42.247Z 
                        ├ [4]  ╭ VulnerabilityID : CVE-2022-35957 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 9.1.6, 9.0.9, 8.5.13 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-35957 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Escalation from admin to server admin when auth
                        │      │                   proxy is used 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. Versions prior to 9.1.6 and 8.5.13 are
                        │      │                   vulnerable to an escalation from admin to server admin when
                        │      │                   auth proxy is used, allowing an admin to take over the
                        │      │                   server admin account and gain full control of the grafana
                        │      │                   instance. All installations should be upgraded as soon as
                        │      │                   possible. As a workaround deactivate auth proxy following
                        │      │                   the instructions at:
                        │      │                   https://grafana.com/docs/grafana/latest/setup-grafana/config
                        │      │                   ure-security/configure-authentication/auth-proxy/ 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ─ [0]: CWE-290 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 3 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 6.6 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 6.6 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
                        │      │                  │         │           H/A:H 
                        │      │                  │         ╰ V3Score : 6.6 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:
                        │      │                            │           H/A:H 
                        │      │                            ╰ V3Score : 6.6 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:2167 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-35957 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2124669 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2125514 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2131149 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2132868 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2132872 
                        │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2023-2167.html 
                        │      │                  ├ [8] : https://github.com/grafana/grafana 
                        │      │                  ├ [9] : https://github.com/grafana/grafana/security/advisorie
                        │      │                  │       s/GHSA-ff5c-938w-8c9q 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2022-35957.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2023-2167.html 
                        │      │                  ├ [12]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce%40lists.fedoraproject.org/message/WYU5C2RIT
                        │      │                  │       LHVZSTCWNGQWA6KSPYNXM2H/ 
                        │      │                  ├ [13]: https://lists.fedoraproject.org/archives/list/package
                        │      │                  │       -announce@lists.fedoraproject.org/message/WYU5C2RITLH
                        │      │                  │       VZSTCWNGQWA6KSPYNXM2H 
                        │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2022-35957 
                        │      │                  ├ [15]: https://security.netapp.com/advisory/ntap-20221215-0001 
                        │      │                  ├ [16]: https://security.netapp.com/advisory/ntap-20221215-00
                        │      │                  │       01/ 
                        │      │                  ╰ [17]: https://www.cve.org/CVERecord?id=CVE-2022-35957 
                        │      ├ PublishedDate   : 2022-09-20T23:15:09.457Z 
                        │      ╰ LastModifiedDate: 2024-11-21T07:12:03.05Z 
                        ├ [5]  ╭ VulnerabilityID : CVE-2022-39307 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 9.2.4, 8.5.15 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39307 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: User enumeration via forget password 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. When using the forget password on the login
                        │      │                   page, a POST request is made to the
                        │      │                   `/api/user/password/sent-reset-email` URL. When the username
                        │      │                    or email does not exist, a JSON response contains a “user
                        │      │                   not found” message. This leaks information to
                        │      │                   unauthenticated users and introduces a security risk. This
                        │      │                   issue has been patched in 9.2.4 and backported to 8.5.15.
                        │      │                   There are no known workarounds. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-200 
                        │      │                  ╰ [1]: CWE-209 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 3 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
                        │      │                  │         │           H/A:L 
                        │      │                  │         ╰ V3Score : 6.7 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 5.3 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:6420 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39307 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2131146 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2131147 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2131148 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2138014 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2138015 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2148252 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/2158420 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/2161274 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/2184483 
                        │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2023-6420.html 
                        │      │                  ├ [12]: https://github.com/grafana/grafana 
                        │      │                  ├ [13]: https://github.com/grafana/grafana/security/advisorie
                        │      │                  │       s/GHSA-3p62-42x7-gxg5 
                        │      │                  ├ [14]: https://grafana.com/blog/2022/11/08/security-release-
                        │      │                  │       new-versions-of-grafana-with-critical-and-moderate-fi
                        │      │                  │       xes-for-cve-2022-39328-cve-2022-39307-and-cve-2022-39
                        │      │                  │       306/ 
                        │      │                  ├ [15]: https://linux.oracle.com/cve/CVE-2022-39307.html 
                        │      │                  ├ [16]: https://linux.oracle.com/errata/ELSA-2023-6420.html 
                        │      │                  ├ [17]: https://nvd.nist.gov/vuln/detail/CVE-2022-39307 
                        │      │                  ├ [18]: https://security.netapp.com/advisory/ntap-20221215-0004 
                        │      │                  ├ [19]: https://security.netapp.com/advisory/ntap-20221215-00
                        │      │                  │       04/ 
                        │      │                  ╰ [20]: https://www.cve.org/CVERecord?id=CVE-2022-39307 
                        │      ├ PublishedDate   : 2022-11-09T23:15:12.617Z 
                        │      ╰ LastModifiedDate: 2024-11-21T07:18:00.08Z 
                        ├ [6]  ╭ VulnerabilityID : CVE-2023-2801 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 9.4.12, 9.5.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-2801 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: data source proxy race condition 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. 
                        │      │                   
                        │      │                   Using public dashboards users can query multiple distinct
                        │      │                   data sources using mixed queries. However such query has a
                        │      │                   possibility of crashing a Grafana instance.
                        │      │                   The only feature that uses mixed queries at the moment is
                        │      │                   public dashboards, but it's also possible to cause this by
                        │      │                   calling the query API directly.
                        │      │                   This might enable malicious users to crash Grafana instances
                        │      │                    through that endpoint.
                        │      │                   Users may upgrade to version 9.4.12 and 9.5.3 to receive a
                        │      │                   fix. 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-820 
                        │      │                  ╰ [1]: CWE-662 
                        │      ├ VendorSeverity   ╭ bitnami: 2 
                        │      │                  ├ ghsa   : 3 
                        │      │                  ├ nvd    : 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 7.5 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:H 
                        │      │                  │         ╰ V3Score : 5.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:H 
                        │      │                            ╰ V3Score : 7.5 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-2801 
                        │      │                  ├ [1]: https://github.com/grafana/grafana 
                        │      │                  ├ [2]: https://grafana.com/security/security-advisories/cve-2
                        │      │                  │      023-2801 
                        │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
                        │      │                  │      023-2801/ 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2023-2801 
                        │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20230706-0002 
                        │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20230706-0002/ 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-2801 
                        │      ├ PublishedDate   : 2023-06-06T19:15:11.413Z 
                        │      ╰ LastModifiedDate: 2025-02-13T17:16:22.81Z 
                        ├ [7]  ╭ VulnerabilityID : CVE-2025-6023 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 1.9.2-0.20250521205822-0ba0b99665a9 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-6023 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Cross Site Scripting in Grafana 
                        │      ├ Description     : An open redirect vulnerability has been identified in
                        │      │                   Grafana OSS that can be exploited to achieve XSS attacks.
                        │      │                   The vulnerability was introduced in Grafana v11.5.0.
                        │      │                   
                        │      │                   The open redirect can be chained with path traversal
                        │      │                   vulnerabilities to achieve XSS.
                        │      │                   Fixed in versions 12.0.2+security-01, 11.6.3+security-01,
                        │      │                   11.5.6+security-01, 11.4.6+security-01 and 11.3.8+security-0
                        │      │                   1 
                        │      ├ Severity        : HIGH 
                        │      ├ CweIDs           ╭ [0]: CWE-79 
                        │      │                  ╰ [1]: CWE-601 
                        │      ├ VendorSeverity   ╭ bitnami: 3 
                        │      │                  ├ ghsa   : 3 
                        │      │                  ╰ redhat : 3 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
                        │      │                  │         │           L/A:L 
                        │      │                  │         ╰ V3Score : 7.6 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:
                        │      │                  │         │           L/A:L 
                        │      │                  │         ╰ V3Score : 7.6 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 7.1 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2025-6023 
                        │      │                  ├ [1] : https://github.com/grafana/grafana 
                        │      │                  ├ [2] : https://github.com/grafana/grafana/commit/0ba0b99665a
                        │      │                  │       946cd96676ef85ec8bc83028cb1d7 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/commit/40ed88fe86d
                        │      │                  │       347bcde5ddaed6c4a20a95d2f0d55 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/commit/5b00e21638f
                        │      │                  │       565eed46acb4d0b7c009968df4c3b 
                        │      │                  ├ [5] : https://github.com/grafana/grafana/commit/b6dd2b70c65
                        │      │                  │       5c61b111b328f1a7dcca6b3954936 
                        │      │                  ├ [6] : https://github.com/grafana/grafana/commit/e0ba4b48095
                        │      │                  │       4f8a33aa2cff3229f6bcc05777bd9 
                        │      │                  ├ [7] : https://grafana.com/blog/2025/07/17/grafana-security-
                        │      │                  │       release-medium-and-high-severity-fixes-for-cve-2025-6
                        │      │                  │       197-and-cve-2025-6023 
                        │      │                  ├ [8] : https://grafana.com/blog/2025/07/17/grafana-security-
                        │      │                  │       release-medium-and-high-severity-fixes-for-cve-2025-6
                        │      │                  │       197-and-cve-2025-6023/ 
                        │      │                  ├ [9] : https://grafana.com/security/security-advisories/cve-
                        │      │                  │       2025-6023 
                        │      │                  ├ [10]: https://grafana.com/security/security-advisories/cve-
                        │      │                  │       2025-6023/ 
                        │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2025-6023 
                        │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2025-6023 
                        │      ├ PublishedDate   : 2025-07-18T08:15:28.04Z 
                        │      ╰ LastModifiedDate: 2025-07-22T13:06:27.983Z 
                        ├ [8]  ╭ VulnerabilityID : CVE-2018-1000816 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 5.3.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-1000816 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Cross site scripting in Influxdb and Graphite query
                        │      │                    editor 
                        │      ├ Description     : Grafana version confirmed for 5.2.4 and 5.3.0 contains a
                        │      │                   Cross Site Scripting (XSS) vulnerability in Influxdb and
                        │      │                   Graphite query editor that can result in Running arbitrary
                        │      │                   js code in victims browser.. This attack appear to be
                        │      │                   exploitable via Authenticated user must click on the input
                        │      │                   field where the payload was previously inserted.. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ ghsa  : 2 
                        │      │                  ├ nvd   : 2 
                        │      │                  ├ redhat: 2 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ╰ V3Score : 5.4 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:S/C:N/I:P/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ├ V2Score : 3.5 
                        │      │                  │        ╰ V3Score : 5.4 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 5.4 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-1000816 
                        │      │                  ├ [1]: https://github.com/grafana/grafana 
                        │      │                  ├ [2]: https://github.com/grafana/grafana/commit/eabb04cec21d
                        │      │                  │      c323347da1aab7fcbf2a6e9dd121 
                        │      │                  ├ [3]: https://github.com/grafana/grafana/issues/13667 
                        │      │                  ├ [4]: https://github.com/grafana/grafana/pull/13670 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2018-1000816 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2018-1000816 
                        │      ├ PublishedDate   : 2018-12-20T15:29:00.643Z 
                        │      ╰ LastModifiedDate: 2024-11-21T03:40:25.107Z 
                        ├ [9]  ╭ VulnerabilityID : CVE-2018-12099 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 5.2.0-beta1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-12099 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Cross-site Scripting (XSS) in dashboard links 
                        │      ├ Description     : Grafana before 5.2.0-beta1 has XSS vulnerabilities in
                        │      │                   dashboard links. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ ghsa  : 2 
                        │      │                  ├ nvd   : 2 
                        │      │                  ├ redhat: 2 
                        │      │                  ╰ ubuntu: 1 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ├ V2Score : 4.3 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 6.8 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-12099 
                        │      │                  ├ [1]: https://github.com/grafana/grafana/pull/11813 
                        │      │                  ├ [2]: https://github.com/grafana/grafana/releases/tag/v5.2.0
                        │      │                  │      -beta1 
                        │      │                  ├ [3]: https://nvd.nist.gov/vuln/detail/CVE-2018-12099 
                        │      │                  ├ [4]: https://security.netapp.com/advisory/ntap-20190416-0004 
                        │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20190416-0004/ 
                        │      │                  ╰ [6]: https://www.cve.org/CVERecord?id=CVE-2018-12099 
                        │      ├ PublishedDate   : 2018-06-11T11:29:00.413Z 
                        │      ╰ LastModifiedDate: 2024-11-21T03:44:35.77Z 
                        ├ [10] ╭ VulnerabilityID : CVE-2018-18623 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 6.0.0-beta1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18623 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: XSS vulnerability via the "Dashboard > Text Panel"
                        │      │                   screen 
                        │      ├ Description     : Grafana 5.3.1 has XSS via the "Dashboard > Text Panel"
                        │      │                   screen. NOTE: this issue exists because of an incomplete fix
                        │      │                    for CVE-2018-12099. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ ghsa  : 2 
                        │      │                  ├ nvd   : 2 
                        │      │                  ├ redhat: 2 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ├ V2Score : 4.3 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-18623 
                        │      │                  ├ [1]: https://github.com/grafana/grafana/issues/15293 
                        │      │                  ├ [2]: https://github.com/grafana/grafana/issues/4117 
                        │      │                  ├ [3]: https://github.com/grafana/grafana/pull/11813 
                        │      │                  ├ [4]: https://github.com/grafana/grafana/pull/14984 
                        │      │                  ├ [5]: https://github.com/grafana/grafana/releases/tag/v6.0.0 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2018-18623 
                        │      │                  ├ [7]: https://security.netapp.com/advisory/ntap-20200608-0008 
                        │      │                  ├ [8]: https://security.netapp.com/advisory/ntap-20200608-0008/ 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2018-18623 
                        │      ├ PublishedDate   : 2020-06-02T17:15:11.427Z 
                        │      ╰ LastModifiedDate: 2024-11-21T03:56:15.137Z 
                        ├ [11] ╭ VulnerabilityID : CVE-2018-18624 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 7.0.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18624 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: XSS vulnerability via a column style on the
                        │      │                   "Dashboard > Table Panel" screen 
                        │      ├ Description     : Grafana 5.3.1 has XSS via a column style on the "Dashboard >
                        │      │                    Table Panel" screen. NOTE: this issue exists because of an
                        │      │                   incomplete fix for CVE-2018-12099. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ├ V2Score : 4.3 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2018-18624 
                        │      │                  ├ [1] : https://github.com/grafana/grafana 
                        │      │                  ├ [2] : https://github.com/grafana/grafana/commit/0284747c88e
                        │      │                  │       b9435899006d26ffaf65f89dec88e 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/pull/11813 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/pull/23816 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2018-18624.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
                        │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2018-18624 
                        │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200608-0008 
                        │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200608-00
                        │      │                  │       08/ 
                        │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2018-18624 
                        │      ├ PublishedDate   : 2020-06-02T17:15:11.487Z 
                        │      ╰ LastModifiedDate: 2024-11-21T03:56:15.3Z 
                        ├ [12] ╭ VulnerabilityID : CVE-2018-18625 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 6.0.0-beta1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2018-18625 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: XSS vulnerability via a link on the "Dashboard >
                        │      │                   All Panels > General" screen 
                        │      ├ Description     : Grafana 5.3.1 has XSS via a link on the "Dashboard > All
                        │      │                   Panels > General" screen. NOTE: this issue exists because of
                        │      │                    an incomplete fix for CVE-2018-12099. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ ghsa  : 2 
                        │      │                  ├ nvd   : 2 
                        │      │                  ├ redhat: 2 
                        │      │                  ╰ ubuntu: 2 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                  │        │           /A:N 
                        │      │                  │        ├ V2Score : 4.3 
                        │      │                  │        ╰ V3Score : 6.1 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2018-18625 
                        │      │                  ├ [1]: https://github.com/grafana/grafana/pull/11813 
                        │      │                  ├ [2]: https://github.com/grafana/grafana/pull/14984 
                        │      │                  ├ [3]: https://github.com/grafana/grafana/pull/22680#issuecom
                        │      │                  │      ment-651195921 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2018-18625 
                        │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20200608-0008 
                        │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20200608-0008/ 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2018-18625 
                        │      ├ PublishedDate   : 2020-06-02T17:15:11.567Z 
                        │      ╰ LastModifiedDate: 2024-11-21T03:56:15.443Z 
                        ├ [13] ╭ VulnerabilityID : CVE-2019-13068 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 6.2.5 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-13068 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : Grafana Cross-site Scripting vulnerability 
                        │      ├ Description     : public/app/features/panel/panel_ctrl.ts in Grafana before
                        │      │                   6.2.5 allows HTML Injection in panel drilldown links (via
                        │      │                   the Title or url field). 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ ghsa: 2 
                        │      │                  ╰ nvd : 2 
                        │      ├ CVSS             ╭ ghsa ╭ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N 
                        │      │                  │      ╰ V3Score : 5.4 
                        │      │                  ╰ nvd  ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                         ├ V3Vector: CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N 
                        │      │                         ├ V2Score : 4.3 
                        │      │                         ╰ V3Score : 5.4 
                        │      ├ References       ╭ [0]: http://packetstormsecurity.com/files/171500/Grafana-6.
                        │      │                  │      2.4-HTML-Injection.html 
                        │      │                  ├ [1]: https://github.com/grafana/grafana 
                        │      │                  ├ [2]: https://github.com/grafana/grafana/issues/17718 
                        │      │                  ├ [3]: https://github.com/grafana/grafana/releases/tag/v6.2.5 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2019-13068 
                        │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20190710-0001 
                        │      │                  ╰ [6]: https://security.netapp.com/advisory/ntap-20190710-0001/ 
                        │      ├ PublishedDate   : 2019-06-30T00:15:11.313Z 
                        │      ╰ LastModifiedDate: 2024-11-21T04:24:08.057Z 
                        ├ [14] ╭ VulnerabilityID : CVE-2019-19499 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 6.4.4 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2019-19499 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: arbitrary file read via MySQL data source 
                        │      ├ Description     : Grafana <= 6.4.3 has an Arbitrary File Read vulnerability,
                        │      │                   which could be exploited by an authenticated attacker that
                        │      │                   has privileges to modify the data source configurations. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-89 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
                        │      │                  │        │           /A:N/E:P 
                        │      │                  │        ╰ V3Score : 6.2 
                        │      │                  ├ nvd    ╭ V2Vector: AV:N/AC:L/Au:S/C:P/I:N/A:N 
                        │      │                  │        ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
                        │      │                  │        │           /A:N 
                        │      │                  │        ├ V2Score : 4 
                        │      │                  │        ╰ V3Score : 6.5 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N
                        │      │                           │           /A:N 
                        │      │                           ╰ V3Score : 6.5 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2019-19499 
                        │      │                  ├ [1] : https://github.com/grafana/grafana 
                        │      │                  ├ [2] : https://github.com/grafana/grafana/blob/master/CHANGE
                        │      │                  │       LOG.md#644-2019-11-06 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/commit/19dbd27c5ca
                        │      │                  │       a1a160bd5854b65a4e1fe2a8a4f00 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/pull/20192 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2019-19499.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
                        │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2019-19499 
                        │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200918-0003 
                        │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200918-00
                        │      │                  │       03/ 
                        │      │                  ├ [10]: https://swarm.ptsecurity.com/grafana-6-4-3-arbitrary-
                        │      │                  │       file-read/ 
                        │      │                  ╰ [11]: https://www.cve.org/CVERecord?id=CVE-2019-19499 
                        │      ├ PublishedDate   : 2020-08-28T15:15:11.953Z 
                        │      ╰ LastModifiedDate: 2024-11-21T04:34:50.603Z 
                        ├ [15] ╭ VulnerabilityID : CVE-2020-11110 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 6.7.2 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-11110 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: stored XSS 
                        │      ├ Description     : Grafana through 6.7.1 allows stored XSS due to insufficient
                        │      │                   input protection in the originalUrl field, which allows an
                        │      │                   attacker to inject JavaScript code that will be executed
                        │      │                   after clicking on Open Original Dashboard after visiting the
                        │      │                    snapshot. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 5.4 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 5.4 
                        │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:S/C:N/I:P/A:N 
                        │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ├ V2Score : 3.5 
                        │      │                  │         ╰ V3Score : 5.4 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-11110 
                        │      │                  ├ [1] : https://github.com/grafana/grafana 
                        │      │                  ├ [2] : https://github.com/grafana/grafana/blob/master/CHANGE
                        │      │                  │       LOG.md 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/commit/fb114a75241
                        │      │                  │       aaef4c08581b42509c750738b768a 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/pull/23254 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-11110.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
                        │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2020-11110 
                        │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200810-0002 
                        │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200810-00
                        │      │                  │       02/ 
                        │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2020-11110 
                        │      ├ PublishedDate   : 2020-07-27T13:15:11.293Z 
                        │      ╰ LastModifiedDate: 2024-11-21T04:56:48.55Z 
                        ├ [16] ╭ VulnerabilityID : CVE-2020-12245 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 6.7.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-12245 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: XSS via column.title or cellLinkTooltip 
                        │      ├ Description     : Grafana before 6.7.3 allows table-panel XSS via column.title
                        │      │                    or cellLinkTooltip. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ├ V2Score : 4.3 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0] : http://lists.opensuse.org/opensuse-security-announce/
                        │      │                  │       2020-06/msg00060.html 
                        │      │                  ├ [1] : http://lists.opensuse.org/opensuse-security-announce/
                        │      │                  │       2020-07/msg00083.html 
                        │      │                  ├ [2] : http://lists.opensuse.org/opensuse-security-announce/
                        │      │                  │       2020-10/msg00009.html 
                        │      │                  ├ [3] : http://lists.opensuse.org/opensuse-security-announce/
                        │      │                  │       2020-10/msg00017.html 
                        │      │                  ├ [4] : https://access.redhat.com/security/cve/CVE-2020-12245 
                        │      │                  ├ [5] : https://community.grafana.com/t/release-notes-v6-7-x/
                        │      │                  │       27119 
                        │      │                  ├ [6] : https://github.com/grafana/grafana 
                        │      │                  ├ [7] : https://github.com/grafana/grafana/blob/master/CHANGE
                        │      │                  │       LOG.md#673-2020-04-23 
                        │      │                  ├ [8] : https://github.com/grafana/grafana/commit/0284747c88e
                        │      │                  │       b9435899006d26ffaf65f89dec88e 
                        │      │                  ├ [9] : https://github.com/grafana/grafana/pull/23816 
                        │      │                  ├ [10]: https://linux.oracle.com/cve/CVE-2020-12245.html 
                        │      │                  ├ [11]: https://linux.oracle.com/errata/ELSA-2020-4682.html 
                        │      │                  ├ [12]: https://nvd.nist.gov/vuln/detail/CVE-2020-12245 
                        │      │                  ├ [13]: https://security.netapp.com/advisory/ntap-20200511-0001 
                        │      │                  ├ [14]: https://security.netapp.com/advisory/ntap-20200511-00
                        │      │                  │       01/ 
                        │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2020-12245 
                        │      ├ PublishedDate   : 2020-04-24T21:15:13.92Z 
                        │      ╰ LastModifiedDate: 2024-11-21T04:59:22.397Z 
                        ├ [17] ╭ VulnerabilityID : CVE-2020-13430 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 7.0.0 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-13430 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: XSS via the OpenTSDB datasource 
                        │      ├ Description     : Grafana before 7.0.0 allows tag value XSS via the OpenTSDB
                        │      │                   datasource. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ├ V2Score : 4.3 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2020-13430 
                        │      │                  ├ [1] : https://github.com/advisories/GHSA-7m2x-qhrq-rp8h 
                        │      │                  ├ [2] : https://github.com/grafana/grafana 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/pull/24539 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/releases/tag/v7.0.0 
                        │      │                  ├ [5] : https://linux.oracle.com/cve/CVE-2020-13430.html 
                        │      │                  ├ [6] : https://linux.oracle.com/errata/ELSA-2020-4682.html 
                        │      │                  ├ [7] : https://nvd.nist.gov/vuln/detail/CVE-2020-13430 
                        │      │                  ├ [8] : https://security.netapp.com/advisory/ntap-20200528-0003 
                        │      │                  ├ [9] : https://security.netapp.com/advisory/ntap-20200528-00
                        │      │                  │       03/ 
                        │      │                  ╰ [10]: https://www.cve.org/CVERecord?id=CVE-2020-13430 
                        │      ├ PublishedDate   : 2020-05-24T18:15:10.097Z 
                        │      ╰ LastModifiedDate: 2024-11-21T05:01:14.78Z 
                        ├ [18] ╭ VulnerabilityID : CVE-2020-24303 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 7.1.0-beta1 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2020-24303 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: XSS via a query alias for the Elasticsearch and
                        │      │                   Testdata datasource 
                        │      ├ Description     : Grafana before 7.1.0-beta 1 allows XSS via a query alias for
                        │      │                    the ElasticSearch datasource. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ bitnami    : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ├ nvd     ╭ V2Vector: AV:N/AC:M/Au:N/C:N/I:P/A:N 
                        │      │                  │         ├ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ├ V2Score : 4.3 
                        │      │                  │         ╰ V3Score : 6.1 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 6.1 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2020-24303 
                        │      │                  ├ [1]: https://github.com/grafana/grafana 
                        │      │                  ├ [2]: https://github.com/grafana/grafana/blob/master/CHANGEL
                        │      │                  │      OG.md#710-beta-1-2020-07-01 
                        │      │                  ├ [3]: https://github.com/grafana/grafana/pull/25401 
                        │      │                  ├ [4]: https://linux.oracle.com/cve/CVE-2020-24303.html 
                        │      │                  ├ [5]: https://linux.oracle.com/errata/ELSA-2021-1859.html 
                        │      │                  ├ [6]: https://nvd.nist.gov/vuln/detail/CVE-2020-24303 
                        │      │                  ├ [7]: https://security.netapp.com/advisory/ntap-20201123-0002 
                        │      │                  ├ [8]: https://security.netapp.com/advisory/ntap-20201123-0002/ 
                        │      │                  ╰ [9]: https://www.cve.org/CVERecord?id=CVE-2020-24303 
                        │      ├ PublishedDate   : 2020-10-28T14:15:12.33Z 
                        │      ╰ LastModifiedDate: 2024-11-21T05:14:34.773Z 
                        ├ [19] ╭ VulnerabilityID : CVE-2022-39229 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 8.5.14, 9.1.8 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39229 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: using email as a username can block other users
                        │      │                   from signing in 
                        │      ├ Description     : Grafana is an open source data visualization platform for
                        │      │                   metrics, logs, and traces. Versions prior to 9.1.8 and
                        │      │                   8.5.14 allow one user to block another user's login attempt
                        │      │                   by registering someone else'e email address as a username. A
                        │      │                    Grafana user’s username and email address are unique
                        │      │                   fields, that means no other user can have the same username
                        │      │                   or email address as another user. A user can have an email
                        │      │                   address as a username. However, the login system allows
                        │      │                   users to log in with either username or email address. Since
                        │      │                    Grafana allows a user to log in with either their username
                        │      │                   or email address, this creates an usual behavior where
                        │      │                   `user_1` can register with one email address and `user_2`
                        │      │                   can register their username as `user_1`’s email address.
                        │      │                   This prevents `user_1` logging into the application since
                        │      │                   `user_1`'s password won’t match with `user_2`'s email
                        │      │                   address. Versions 9.1.8 and 8.5.14 contain a patch. There
                        │      │                   are no workarounds for this issue. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-287 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 2 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 2 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 1 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:L 
                        │      │                  │         ╰ V3Score : 4.3 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:L 
                        │      │                  │         ╰ V3Score : 4.3 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
                        │      │                  │         │           N/A:L 
                        │      │                  │         ╰ V3Score : 4.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
                        │      │                            │           N/A:L 
                        │      │                            ╰ V3Score : 4.3 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:2167 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39229 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2124669 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2125514 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2131149 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2132868 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2132872 
                        │      │                  ├ [7] : https://errata.almalinux.org/9/ALSA-2023-2167.html 
                        │      │                  ├ [8] : https://github.com/grafana/grafana 
                        │      │                  ├ [9] : https://github.com/grafana/grafana/commit/5644758f0c5
                        │      │                  │       ae9955a4e5480d71f9bef57fdce35 
                        │      │                  ├ [10]: https://github.com/grafana/grafana/releases/tag/v9.1.8 
                        │      │                  ├ [11]: https://github.com/grafana/grafana/security/advisorie
                        │      │                  │       s/GHSA-gj7m-853r-289r 
                        │      │                  ├ [12]: https://linux.oracle.com/cve/CVE-2022-39229.html 
                        │      │                  ├ [13]: https://linux.oracle.com/errata/ELSA-2023-2784.html 
                        │      │                  ├ [14]: https://nvd.nist.gov/vuln/detail/CVE-2022-39229 
                        │      │                  ╰ [15]: https://www.cve.org/CVERecord?id=CVE-2022-39229 
                        │      ├ PublishedDate   : 2022-10-13T23:15:10.937Z 
                        │      ╰ LastModifiedDate: 2024-11-21T07:17:50.027Z 
                        ├ [20] ╭ VulnerabilityID : CVE-2022-39324 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 9.2.8, 8.5.16 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2022-39324 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Spoofing of the originalUrl parameter of snapshots 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. Prior to versions 8.5.16 and 9.2.8, malicious
                        │      │                    user can create a snapshot and arbitrarily choose the
                        │      │                   `originalUrl` parameter by editing the query, thanks to a
                        │      │                   web proxy. When another user opens the URL of the snapshot,
                        │      │                   they will be presented with the regular web interface
                        │      │                   delivered by the trusted Grafana server. The `Open original
                        │      │                   dashboard` button no longer points to the to the real
                        │      │                   original dashboard but to the attacker’s injected URL. This
                        │      │                   issue is fixed in versions 8.5.16 and 9.2.8. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-79 
                        │      ├ VendorSeverity   ╭ alma       : 2 
                        │      │                  ├ bitnami    : 1 
                        │      │                  ├ ghsa       : 2 
                        │      │                  ├ nvd        : 1 
                        │      │                  ├ oracle-oval: 2 
                        │      │                  ├ redhat     : 2 
                        │      │                  ╰ ubuntu     : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 3.5 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
                        │      │                  │         │           H/A:L 
                        │      │                  │         ╰ V3Score : 6.7 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 3.5 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:
                        │      │                            │           H/A:L 
                        │      │                            ╰ V3Score : 6.7 
                        │      ├ References       ╭ [0] : https://access.redhat.com/errata/RHSA-2023:6420 
                        │      │                  ├ [1] : https://access.redhat.com/security/cve/CVE-2022-39324 
                        │      │                  ├ [2] : https://bugzilla.redhat.com/2131146 
                        │      │                  ├ [3] : https://bugzilla.redhat.com/2131147 
                        │      │                  ├ [4] : https://bugzilla.redhat.com/2131148 
                        │      │                  ├ [5] : https://bugzilla.redhat.com/2138014 
                        │      │                  ├ [6] : https://bugzilla.redhat.com/2138015 
                        │      │                  ├ [7] : https://bugzilla.redhat.com/2148252 
                        │      │                  ├ [8] : https://bugzilla.redhat.com/2158420 
                        │      │                  ├ [9] : https://bugzilla.redhat.com/2161274 
                        │      │                  ├ [10]: https://bugzilla.redhat.com/2184483 
                        │      │                  ├ [11]: https://errata.almalinux.org/9/ALSA-2023-6420.html 
                        │      │                  ├ [12]: https://github.com/grafana/grafana 
                        │      │                  ├ [13]: https://github.com/grafana/grafana/commit/239888f2298
                        │      │                  │       3010576bb3a9135a7294e88c0c74a 
                        │      │                  ├ [14]: https://github.com/grafana/grafana/commit/d7dcea71ea7
                        │      │                  │       63780dc286792a0afd560bff2985c 
                        │      │                  ├ [15]: https://github.com/grafana/grafana/pull/60232 
                        │      │                  ├ [16]: https://github.com/grafana/grafana/pull/60256 
                        │      │                  ├ [17]: https://github.com/grafana/grafana/security/advisorie
                        │      │                  │       s/GHSA-4724-7jwc-3fpw 
                        │      │                  ├ [18]: https://grafana.com/blog/2023/01/25/grafana-security-
                        │      │                  │       releases-new-versions-with-fixes-for-cve-2022-23552-c
                        │      │                  │       ve-2022-41912-and-cve-2022-39324/ 
                        │      │                  ├ [19]: https://linux.oracle.com/cve/CVE-2022-39324.html 
                        │      │                  ├ [20]: https://linux.oracle.com/errata/ELSA-2023-6420.html 
                        │      │                  ├ [21]: https://nvd.nist.gov/vuln/detail/CVE-2022-39324 
                        │      │                  ├ [22]: https://security.netapp.com/advisory/ntap-20230309-00
                        │      │                  │       10/ 
                        │      │                  ╰ [23]: https://www.cve.org/CVERecord?id=CVE-2022-39324 
                        │      ├ PublishedDate   : 2023-01-27T23:15:08.723Z 
                        │      ╰ LastModifiedDate: 2024-11-21T07:18:02.36Z 
                        ├ [21] ╭ VulnerabilityID : CVE-2023-2183 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 8.5.26, 9.2.19, 9.3.15, 9.4.12, 9.5.3 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-2183 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: missing access control allows test alerts by
                        │      │                   underprivileged user 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. 
                        │      │                   
                        │      │                   The option to send a test alert is not available from the
                        │      │                   user panel UI for users having the Viewer role. It is still
                        │      │                   possible for a user with the Viewer role to send a test
                        │      │                   alert using the API as the API does not check access to this
                        │      │                    function.
                        │      │                   This might enable malicious users to abuse the functionality
                        │      │                    by sending multiple alert messages to e-mail and Slack,
                        │      │                   spamming users, prepare Phishing attack or block SMTP
                        │      │                   server.
                        │      │                   Users may upgrade to version 9.5.3, 9.4.12, 9.3.15, 9.2.19
                        │      │                   and 8.5.26 to receive a fix. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ╭ [0]: CWE-284 
                        │      │                  ╰ [1]: CWE-862 
                        │      ├ VendorSeverity   ╭ bitnami: 2 
                        │      │                  ├ ghsa   : 2 
                        │      │                  ├ nvd    : 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.4 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 4.1 
                        │      │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:
                        │      │                  │         │           L/A:N 
                        │      │                  │         ╰ V3Score : 6.4 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:
                        │      │                            │           L/A:N 
                        │      │                            ╰ V3Score : 4.3 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-2183 
                        │      │                  ├ [1]: https://github.com/grafana/bugbounty 
                        │      │                  ├ [2]: https://github.com/grafana/bugbounty/security/advisori
                        │      │                  │      es/GHSA-cvm3-pp2j-chr3 
                        │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
                        │      │                  │      023-2183 
                        │      │                  ├ [4]: https://grafana.com/security/security-advisories/cve-2
                        │      │                  │      023-2183/ 
                        │      │                  ├ [5]: https://nvd.nist.gov/vuln/detail/CVE-2023-2183 
                        │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20230706-0002/ 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-2183 
                        │      ├ PublishedDate   : 2023-06-06T19:15:11.277Z 
                        │      ╰ LastModifiedDate: 2025-02-13T17:16:19.957Z 
                        ├ [22] ╭ VulnerabilityID : CVE-2023-4822 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ Status          : affected 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2023-4822 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: incorrect assessment of permissions across
                        │      │                   organizations 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. The vulnerability impacts Grafana instances
                        │      │                   with several organizations, and allows a user with
                        │      │                   Organization Admin permissions in one organization to change
                        │      │                    the permissions associated with Organization Viewer,
                        │      │                   Organization Editor and Organization Admin roles in all
                        │      │                   organizations.
                        │      │                   
                        │      │                   It also allows an Organization Admin to assign or revoke any
                        │      │                    permissions that they have to any user globally.
                        │      │                   This means that any Organization Admin can elevate their own
                        │      │                    permissions in any organization that they are already a
                        │      │                   member of, or elevate or restrict the permissions of any
                        │      │                   other user.
                        │      │                   The vulnerability does not allow a user to become a member
                        │      │                   of an organization that they are not already a member of, or
                        │      │                    to add any other users to an organization that the current
                        │      │                   user is not a member of. 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-269 
                        │      ├ VendorSeverity   ╭ ghsa  : 2 
                        │      │                  ├ nvd   : 3 
                        │      │                  ╰ redhat: 2 
                        │      ├ CVSS             ╭ ghsa   ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
                        │      │                  │        │           /A:L 
                        │      │                  │        ╰ V3Score : 6.7 
                        │      │                  ├ nvd    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
                        │      │                  │        │           /A:H 
                        │      │                  │        ╰ V3Score : 7.2 
                        │      │                  ╰ redhat ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H
                        │      │                           │           /A:L 
                        │      │                           ╰ V3Score : 6.7 
                        │      ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2023-4822 
                        │      │                  ├ [1]: https://github.com/grafana/grafana 
                        │      │                  ├ [2]: https://grafana.com/blog/2023/10/13/grafana-security-r
                        │      │                  │      elease-new-versions-of-grafana-with-a-medium-severity-
                        │      │                  │      security-fix-for-cve-2023-4822/ 
                        │      │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
                        │      │                  │      023-4822 
                        │      │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2023-4822 
                        │      │                  ├ [5]: https://security.netapp.com/advisory/ntap-20231103-0008 
                        │      │                  ├ [6]: https://security.netapp.com/advisory/ntap-20231103-0008/ 
                        │      │                  ╰ [7]: https://www.cve.org/CVERecord?id=CVE-2023-4822 
                        │      ├ PublishedDate   : 2023-10-16T09:15:11.687Z 
                        │      ╰ LastModifiedDate: 2025-06-16T17:15:27.72Z 
                        ├ [23] ╭ VulnerabilityID : CVE-2025-3415 
                        │      ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                        │      │                   6+dirty 
                        │      ├ PkgName         : github.com/grafana/grafana 
                        │      ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                        │      │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                        │      │                  ╰ UID : 8eebf1780b834016 
                        │      ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                        │      ├ FixedVersion    : 1.9.2-0.20250514160932-04111e9f2afd 
                        │      ├ Status          : fixed 
                        │      ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                        │      │                  │         f0cd2bf50b021cbc8562 
                        │      │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                        │      │                            a26c555f5f835bf9a62c 
                        │      ├ SeveritySource  : ghsa 
                        │      ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2025-3415 
                        │      ├ DataSource       ╭ ID  : ghsa 
                        │      │                  ├ Name: GitHub Security Advisory Go 
                        │      │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                        │      │                          cosystem%3Ago 
                        │      ├ Title           : grafana: Exposure of DingDing alerting integration URL to
                        │      │                   Viewer level users 
                        │      ├ Description     : Grafana is an open-source platform for monitoring and
                        │      │                   observability. The Grafana Alerting DingDing integration was
                        │      │                    not properly protected and could be exposed to users with
                        │      │                   Viewer permission. 
                        │      │                   Fixed in versions 10.4.19+security-01, 11.2.10+security-01,
                        │      │                   11.3.7+security-01, 11.4.5+security-01, 11.5.5+security-01,
                        │      │                   11.6.2+security-01 and 12.0.1+security-01 
                        │      ├ Severity        : MEDIUM 
                        │      ├ CweIDs           ─ [0]: CWE-200 
                        │      ├ VendorSeverity   ╭ bitnami: 2 
                        │      │                  ├ ghsa   : 2 
                        │      │                  ╰ redhat : 2 
                        │      ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 4.3 
                        │      │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
                        │      │                  │         │           N/A:N 
                        │      │                  │         ╰ V3Score : 4.3 
                        │      │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:
                        │      │                            │           N/A:N 
                        │      │                            ╰ V3Score : 4.3 
                        │      ├ References       ╭ [0] : https://access.redhat.com/security/cve/CVE-2025-3415 
                        │      │                  ├ [1] : https://github.com/grafana/grafana 
                        │      │                  ├ [2] : https://github.com/grafana/grafana/commit/04111e9f2af
                        │      │                  │       d95ea3e5b01865cc29d3fc1198e71 
                        │      │                  ├ [3] : https://github.com/grafana/grafana/commit/0adb869188f
                        │      │                  │       a2b9ae26efd424b94e17189538f29 
                        │      │                  ├ [4] : https://github.com/grafana/grafana/commit/19c912476d4
                        │      │                  │       f7a81e8a3562668bc38f31b909e18 
                        │      │                  ├ [5] : https://github.com/grafana/grafana/commit/4144c636d1a
                        │      │                  │       6d0b17fafcf7a2c40fa403542202a 
                        │      │                  ├ [6] : https://github.com/grafana/grafana/commit/4fc33647a82
                        │      │                  │       97d3a0aae04a5fcbac883ceb6a655 
                        │      │                  ├ [7] : https://github.com/grafana/grafana/commit/910eb1dd9e6
                        │      │                  │       18014c6b1d2a99a431b99d4268c05 
                        │      │                  ├ [8] : https://github.com/grafana/grafana/commit/91327938626
                        │      │                  │       c9426e481e6294850af7b61415c98 
                        │      │                  ├ [9] : https://github.com/grafana/grafana/commit/a78de30720b
                        │      │                  │       4f33c88d0c1a973e693ebf3831717 
                        │      │                  ├ [10]: https://grafana.com/security/security-advisories/cve-
                        │      │                  │       2025-3415 
                        │      │                  ├ [11]: https://nvd.nist.gov/vuln/detail/CVE-2025-3415 
                        │      │                  ╰ [12]: https://www.cve.org/CVERecord?id=CVE-2025-3415 
                        │      ├ PublishedDate   : 2025-07-17T11:15:22.24Z 
                        │      ╰ LastModifiedDate: 2025-07-17T21:15:50.197Z 
                        ╰ [24] ╭ VulnerabilityID : CVE-2024-10452 
                               ├ PkgID           : github.com/grafana/grafana@v0.0.0-20250718201843-ccd7b6ce7ea
                               │                   6+dirty 
                               ├ PkgName         : github.com/grafana/grafana 
                               ├ PkgIdentifier    ╭ PURL: pkg:golang/github.com/grafana/grafana@v0.0.0-20250718
                               │                  │       201843-ccd7b6ce7ea6%2Bdirty 
                               │                  ╰ UID : 8eebf1780b834016 
                               ├ InstalledVersion: v0.0.0-20250718201843-ccd7b6ce7ea6+dirty 
                               ├ Status          : affected 
                               ├ Layer            ╭ Digest: sha256:cb64939deae135f24f0cac5c121beae8551dc0f53ddd
                               │                  │         f0cd2bf50b021cbc8562 
                               │                  ╰ DiffID: sha256:ce37ac9563e76948f819b89de5a694438e79d7e6040d
                               │                            a26c555f5f835bf9a62c 
                               ├ SeveritySource  : ghsa 
                               ├ PrimaryURL      : https://avd.aquasec.com/nvd/cve-2024-10452 
                               ├ DataSource       ╭ ID  : ghsa 
                               │                  ├ Name: GitHub Security Advisory Go 
                               │                  ╰ URL : https://github.com/advisories?query=type%3Areviewed+e
                               │                          cosystem%3Ago 
                               ├ Title           : grafana: Org admin can delete pending invites in different org 
                               ├ Description     : Organization admins can delete pending invites created in an
                               │                    organization they are not part of. 
                               ├ Severity        : LOW 
                               ├ CweIDs           ─ [0]: CWE-639 
                               ├ VendorSeverity   ╭ bitnami: 1 
                               │                  ├ ghsa   : 1 
                               │                  ├ nvd    : 1 
                               │                  ╰ redhat : 1 
                               ├ CVSS             ╭ bitnami ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 2.7 
                               │                  ├ ghsa    ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 2.2 
                               │                  ├ nvd     ╭ V3Vector: CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:
                               │                  │         │           L/A:N 
                               │                  │         ╰ V3Score : 2.7 
                               │                  ╰ redhat  ╭ V3Vector: CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:
                               │                            │           L/A:N 
                               │                            ╰ V3Score : 2.2 
                               ├ References       ╭ [0]: https://access.redhat.com/security/cve/CVE-2024-10452 
                               │                  ├ [1]: https://github.com/advisories/GHSA-66c4-2g2v-54qw 
                               │                  ├ [2]: https://github.com/grafana/grafana 
                               │                  ├ [3]: https://grafana.com/security/security-advisories/cve-2
                               │                  │      024-10452 
                               │                  ├ [4]: https://nvd.nist.gov/vuln/detail/CVE-2024-10452 
                               │                  ╰ [5]: https://www.cve.org/CVERecord?id=CVE-2024-10452 
                               ├ PublishedDate   : 2024-10-29T16:15:04.593Z 
                               ╰ LastModifiedDate: 2024-11-08T17:59:10.977Z 
````
